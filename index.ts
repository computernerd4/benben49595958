import { spawn } from "node:child_process";
import crypto from "node:crypto";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { Socket } from "node:net";
import path from "node:path";
import zlib from "node:zlib";

EventEmitter.defaultMaxListeners = 50;

import fastifyMiddie from "@fastify/middie";
import fastifyStatic from "@fastify/static";
import { server as wisp } from "@mercuryworkshop/wisp-js/server";
import { build } from "astro";
import Fastify from "fastify";
import INConfig from "./config";
import { ASSET_FOLDERS, generateMaps, getClientScript, type ObfuscationMaps, ROUTES, transformCss, transformHtml, transformJs } from "./src/lib/obfuscate";
import { getTextCanvasClientScript, transformTextInHtml } from "./src/lib/text-canvas";

let obfuscationMaps: ObfuscationMaps | null = null;

async function Start() {
  const FirstRun = process.env.FIRST === "true";

  if (!fs.existsSync("dist")) {
    console.log("Interstellar's not built yet! Building now...");

    await build({}).catch((err) => {
      console.error("Build failed:", err);
      process.exit(1);
    });

    if (FirstRun) {
      console.log("Restarting Server...");
      const disable = spawn("bun", ["run", "disable"], { stdio: "inherit" });
      disable.on("close", (code) => {
        if (code === 0) {
          const start = spawn("bun", ["start"], { stdio: "inherit" });
          start.on("close", () => process.exit(0));
        } else {
          process.exit(code ?? 1);
        }
      });
      return;
    }
  }

  if (INConfig.server?.obfuscate !== false) {
    obfuscationMaps = generateMaps();
  }

  const port = INConfig.server?.port || 8080;

  const app = Fastify({
    serverFactory: (handler) => createServer(handler).on("upgrade", (req, socket: Socket, head) => (req.url?.startsWith("/f") ? wisp.routeRequest(req, socket, head) : socket.destroy())),
  });

  if (INConfig.server?.compress !== false) {
    await app.register(import("@fastify/compress"), {
      encodings: ["br", "gzip", "deflate"],
    });
  }

  const sitePassword = process.env.SITE_PASSWORD;
  if (sitePassword) {
    const authToken = crypto.createHmac("sha256", "interstellar-gate-v1").update(sitePassword).digest("hex");

    const getLoginPage = (error: boolean) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Ben</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #111;
      font-family: system-ui, -apple-system, sans-serif;
    }
    .card {
      background: #1a1a1a;
      border: 1px solid #2a2a2a;
      border-radius: 16px;
      padding: 48px 40px;
      width: 100%;
      max-width: 380px;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 24px;
    }
    .logo { width: 90px; height: 90px; object-fit: contain; }
    .subtitle { color: #666; font-size: 0.85rem; margin-top: -16px; }
    form { width: 100%; display: flex; flex-direction: column; gap: 12px; }
    input[type="password"] {
      width: 100%;
      padding: 12px 16px;
      background: #222;
      border: 1px solid ${error ? "#e55" : "#333"};
      border-radius: 8px;
      color: #fff;
      font-size: 1rem;
      outline: none;
      transition: border-color 0.2s;
    }
    input[type="password"]:focus { border-color: #555; }
    .error { color: #e55; font-size: 0.8rem; text-align: center; ${error ? "" : "display:none"} }
    button {
      width: 100%;
      padding: 12px;
      background: #fff;
      color: #111;
      border: none;
      border-radius: 8px;
      font-size: 1rem;
      font-weight: 700;
      cursor: pointer;
      transition: opacity 0.2s;
    }
    button:hover { opacity: 0.85; }
  </style>
</head>
<body>
  <div class="card">
    <img class="logo" src="/logo.png" alt="Ben" />
    <p class="subtitle">you didn't get this from us.</p>
    <form method="POST" action="/__auth">
      <input type="password" name="password" placeholder="Enter password" autofocus autocomplete="current-password">
      <p class="error">Incorrect password. Try again.</p>
      <button type="submit">Enter</button>
    </form>
  </div>
</body>
</html>`;

    app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string" }, (_req, body, done) => {
      try {
        const parsed = Object.fromEntries(new URLSearchParams(body as string));
        done(null, parsed);
      } catch (e) {
        done(e as Error);
      }
    });

    const savePassword = sitePassword + "save";
    const classroomPassword = sitePassword + "classroom";
    const SESSION_TTL_MS = 10 * 60 * 1000;
    const sessionTokens = new Map<string, number>();

    setInterval(() => {
      const now = Date.now();
      for (const [token, lastSeen] of sessionTokens) {
        if (now - lastSeen > SESSION_TTL_MS) sessionTokens.delete(token);
      }
    }, 60_000);

    app.get("/__logout", (_req, reply) => {
      reply
        .header("Set-Cookie", `__auth=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`)
        .header("Set-Cookie", `__sess=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`)
        .redirect("/", 302);
    });

    app.post("/__auth", (req, reply) => {
      const body = req.body as { password?: string };
      const entered = body?.password || "";
      if (entered === classroomPassword) {
        reply
          .header("Set-Cookie", `__auth=${authToken}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000`)
          .redirect("https://classroom.google.com/", 302);
      } else if (entered === savePassword) {
        reply.redirect("https://www.google.com", 302);
      } else if (entered === sitePassword) {
        const sessToken = crypto.randomBytes(32).toString("hex");
        sessionTokens.set(sessToken, Date.now());
        reply
          .header("Set-Cookie", `__sess=${sessToken}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400`)
          .redirect("/", 302);
      } else {
        reply.type("text/html; charset=utf-8").code(401).send(getLoginPage(true));
      }
    });

    app.addHook("onRequest", (req, reply, done) => {
      if (req.url === "/__auth" || req.url === "/__logout" || req.url === "/logo.png") {
        done();
        return;
      }
      const cookieHeader = req.headers.cookie || "";
      const authMatch = cookieHeader.match(/(?:^|;\s*)__auth=([^;]*)/);
      const sessMatch = cookieHeader.match(/(?:^|;\s*)__sess=([^;]*)/);
      const authVal = authMatch ? decodeURIComponent(authMatch[1]) : null;
      const sessVal = sessMatch ? decodeURIComponent(sessMatch[1]) : null;
      if (authVal === authToken) {
        done();
        return;
      }
      if (sessVal) {
        const lastSeen = sessionTokens.get(sessVal);
        if (lastSeen && Date.now() - lastSeen < SESSION_TTL_MS) {
          sessionTokens.set(sessVal, Date.now());
          done();
          return;
        }
      }
      reply.type("text/html; charset=utf-8").send(getLoginPage(false));
    });
  }

  if (INConfig.auth?.challenge) {
    await app.register(import("@fastify/basic-auth"), {
      authenticate: true,
      validate(username, password, _req, _reply, done) {
        const users = INConfig.auth?.users || {};
        const storedPass = users[username];

        if (!storedPass) {
          const dummyPass = crypto.randomBytes(32).toString("hex");
          const inputBuf = Buffer.from(password);
          const dummyBuf = Buffer.alloc(inputBuf.length, dummyPass);
          crypto.timingSafeEqual(inputBuf, dummyBuf);
          return done(new Error("Invalid credentials"));
        }

        const inputBuf = Buffer.from(password);
        const storedBuf = Buffer.from(storedPass);

        if (inputBuf.length !== storedBuf.length) {
          const inputHash = crypto.createHash("sha256").update(password).digest();
          const storedHash = crypto.createHash("sha256").update(storedPass).digest();
          if (crypto.timingSafeEqual(inputHash, storedHash)) {
            return done();
          }
          return done(new Error("Invalid credentials"));
        }

        if (crypto.timingSafeEqual(inputBuf, storedBuf)) {
          return done();
        }
        return done(new Error("Invalid credentials"));
      },
    });
    await app.after();
    app.addHook("onRequest", app.basicAuth);
  }

  if (obfuscationMaps) {
    const reverseRoutes = obfuscationMaps.reverseRoutes;
    const reverseAssets = obfuscationMaps.reverseAssets;
    const literalRoutes = new Set<string>(ROUTES);
    const literalAssetFolders = new Set<string>(ASSET_FOLDERS);

    app.addHook("onRequest", (req, reply, done) => {
      if (req.headers) {
        req.headers["accept-encoding"] = "identity";
      }
      const rawHeaders = (req.raw as { headers?: Record<string, string> }).headers;
      if (rawHeaders) {
        rawHeaders["accept-encoding"] = "identity";
      }

      const [urlPath, query] = req.url.split("?");
      const pathParts = urlPath.split("/").filter(Boolean);
      let modified = false;

      if (pathParts.length > 0) {
        const firstPart = pathParts[0];

        if (literalRoutes.has(firstPart)) {
          reply.code(404).send("Not Found");
          return;
        }

        if (firstPart === "assets" && pathParts.length >= 2) {
          const assetFolder = pathParts[1];
          if (literalAssetFolders.has(assetFolder)) {
            reply.code(404).send("Not Found");
            return;
          }
        }

        const realRoute = reverseRoutes[firstPart];
        if (realRoute && realRoute !== "scramjet") {
          pathParts[0] = realRoute;
          modified = true;
        }

        if (pathParts[0] === "assets" && pathParts.length >= 2) {
          const assetFolder = pathParts[1];
          const realFolder = reverseAssets[assetFolder];
          if (realFolder && realFolder !== "scramjet") {
            pathParts[1] = realFolder;
            modified = true;
          }

          if (pathParts.length >= 3) {
            const fileName = pathParts[2];
            const lastDot = fileName.lastIndexOf(".");
            const baseName = lastDot > 0 ? fileName.slice(0, lastDot) : fileName;
            const ext = lastDot > 0 ? fileName.slice(lastDot) : "";
            const realBaseName = reverseAssets[baseName];
            if (realBaseName) {
              pathParts[2] = realBaseName + ext;
              modified = true;
            }
          }
        }
      }

      if (modified) {
        const newUrl = `/${pathParts.join("/")}${query ? `?${query}` : ""}`;
        (req.raw as { url?: string }).url = newUrl;
        Object.defineProperty(req, "url", {
          value: newUrl,
          writable: true,
          configurable: true,
        });
      }

      done();
    });
  }

  if (obfuscationMaps) {
    const assets = obfuscationMaps.assets;
    const routes = obfuscationMaps.routes;
    const scramjetFolder = assets.scramjet;
    const scramjetRoute = routes.scramjet;
    const sjAll = assets["scramjet.all"];

    app.get("/sw.js", (_req, reply) => {
      const swCode = `importScripts("/assets/${scramjetFolder}/${sjAll}.js");

const { ScramjetServiceWorker } = $scramjetLoadWorker();
const scramjet = new ScramjetServiceWorker();
const scramjetPrefix = "/${scramjetRoute}/";

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(clients.claim()));
self.addEventListener("message", (event) => {
  if (event.data && event.data.type === "skipWaiting") {
    self.skipWaiting();
  }
});

self.addEventListener("fetch", (event) => {
  event.respondWith(
    (async () => {
      await scramjet.loadConfig();
      try {
        const url = new URL(event.request.url);
        if (!url.pathname.startsWith(scramjetPrefix)) {
          return fetch(event.request);
        }
      } catch (_e) {}
      if (scramjet.route(event)) {
        return scramjet.fetch(event);
      }
      return fetch(event.request);
    })()
  );
});
`;
      reply.header("Service-Worker-Allowed", "/").type("application/javascript").send(swCode);
    });

    app.get(`/assets/${scramjetFolder}/*`, (req, reply) => {
      const fileName = req.url.split("/").pop() || "";
      let realFileName = fileName;
      for (const [original, obfuscated] of Object.entries(assets)) {
        if (fileName.startsWith(obfuscated)) {
          const ext = fileName.slice(obfuscated.length);
          realFileName = original + ext;
          break;
        }
      }
      reply.header("Access-Control-Allow-Origin", "*");
      return reply.sendFile(`assets/scramjet/${realFileName}`, path.join(import.meta.dirname, "dist", "client"));
    });

    app.get(`/${scramjetRoute}/*`, (req, reply) => {
      const encodedPath = req.url.slice(`/${scramjetRoute}/`.length);
      let targetUrl = "";
      try {
        targetUrl = decodeURIComponent(encodedPath);
      } catch {
        targetUrl = encodedPath;
      }

      const tabsRoute = routes.tabs;

      const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Loading proxy...</title>
  <style>
    body {
      font-family: system-ui, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100vh;
      margin: 0;
      background: #1a1a1a;
      color: #fff;
    }
  </style>
</head>
<body>
  <div id="status">Initializing...</div>
  <script type="module">
    const status = document.getElementById('status');
    const targetUrl = ${JSON.stringify(targetUrl)};

    async function init() {
      try {
        status.textContent = 'Setting up transport...';

        const { BareMuxConnection } = await import('/assets/bundled/bm-index.mjs');
        const connection = new BareMuxConnection("/assets/bundled/bm-worker.js");
        const wispUrl = (location.protocol === "http:" ? "ws:" : "wss:") + "//" + location.host + "/f/";
        await connection.setTransport("/assets/bundled/ex-index.mjs", [{ wisp: wispUrl }]);

        status.textContent = 'Transport ready, loading page...';

        if (targetUrl && targetUrl.startsWith('http')) {
          sessionStorage.setItem('goUrl', targetUrl);
        }

        await new Promise(r => setTimeout(r, 200));
        location.replace('/${tabsRoute}');

      } catch (e) {
        status.textContent = 'Error: ' + e.message;
        console.error('Init error:', e);
      }
    }

    init();
  </script>
</body>
</html>`;

      reply.type("text/html; charset=utf-8").send(html);
    });
  }

  app.addHook("onSend", (_request, reply, _payload, done) => {
    reply.header("X-Content-Type-Options", "nosniff");

    reply.header("Referrer-Policy", "strict-origin-when-cross-origin");
    reply.header("Permissions-Policy", "geolocation=(self), microphone=(self), camera=(self)");
    reply.header("X-XSS-Protection", "1; mode=block");
    const ct = reply.getHeader("content-type");
    if (ct && String(ct).toLowerCase().includes("text/html")) {
      reply.header("Pragma", "no-cache");
    }
    done();
  });

  const { handler } = (await import("./dist/server/entry.mjs")) as {
    handler: (req: unknown, res: unknown, next?: () => void) => void;
  };
  await app
    .register(fastifyStatic, {
      root: path.join(import.meta.dirname, "dist", "client"),
    })
    .register(fastifyMiddie);

  if (obfuscationMaps) {
    const maps = obfuscationMaps;
    const routeScript = getClientScript(maps);
    const textScript = getTextCanvasClientScript(maps.textKey);

    const transformMiddleware = (_req: IncomingMessage, res: ServerResponse, next: () => void) => {
      const originalWriteHead = res.writeHead.bind(res);
      const originalWrite = res.write.bind(res);
      const originalEnd = res.end.bind(res);
      const originalSetHeader = res.setHeader.bind(res);
      const originalRemoveHeader = res.removeHeader.bind(res);

      let contentType: "html" | "js" | "css" | null = null;
      let statusCode = 200;
      let headers: Record<string, string | string[] | number | undefined> = {};
      const chunks: Buffer[] = [];

      const detectContentType = (ct: string): "html" | "js" | "css" | null => {
        const lower = ct.toLowerCase();
        if (lower.includes("text/html")) return "html";
        if (lower.includes("text/css")) return "css";
        if (lower.includes("application/javascript") || lower.includes("text/javascript") || lower.includes("application/x-javascript") || lower.includes("application/ecmascript")) {
          return "js";
        }
        return null;
      };

      const pushChunk = (chunks: Buffer[], chunk: unknown, encoding?: BufferEncoding): void => {
        if (Buffer.isBuffer(chunk)) {
          chunks.push(chunk);
        } else if (chunk instanceof Uint8Array) {
          chunks.push(Buffer.from(chunk));
        } else if (typeof chunk === "string") {
          chunks.push(Buffer.from(chunk, encoding || "utf8"));
        }
      };

      res.setHeader = (name: string, value: string | number | readonly string[]): ServerResponse => {
        const nameLower = name.toLowerCase();
        if (nameLower === "content-type") {
          contentType = detectContentType(String(value));
        }
        if (contentType && (nameLower === "content-encoding" || nameLower === "transfer-encoding")) {
          return res;
        }
        return originalSetHeader(name, value);
      };

      res.writeHead = (code: number, reasonOrHeaders?: any, headersArg?: any): ServerResponse => {
        statusCode = code;
        const h = typeof reasonOrHeaders === "object" ? reasonOrHeaders : headersArg || {};
        headers = { ...headers, ...h };

        const ct = (h["content-type"] || h["Content-Type"] || "").toString();
        if (ct) {
          contentType = contentType || detectContentType(ct);
        }

        if (!contentType) {
          const existingCt = res.getHeader("content-type");
          if (existingCt) {
            contentType = detectContentType(String(existingCt));
          }
        }

        if (contentType) {
          delete headers["content-encoding"];
          delete headers["Content-Encoding"];
          delete headers["transfer-encoding"];
          delete headers["Transfer-Encoding"];
          originalRemoveHeader("content-encoding");
          originalRemoveHeader("transfer-encoding");
          return res;
        }

        return originalWriteHead(code, reasonOrHeaders, headersArg);
      };

      res.write = (chunk: any, encodingOrCb?: any, cb?: any): boolean => {
        if (contentType && chunk) {
          const enc = typeof encodingOrCb === "string" ? (encodingOrCb as BufferEncoding) : undefined;
          pushChunk(chunks, chunk, enc);
          const callback = typeof encodingOrCb === "function" ? encodingOrCb : cb;
          if (typeof callback === "function") callback();
          return true;
        }
        return originalWrite(chunk, encodingOrCb, cb);
      };

      res.end = (chunk?: any, encodingOrCb?: any, cb?: any): ServerResponse => {
        if (contentType) {
          if (chunk && typeof chunk !== "function") {
            const enc = typeof encodingOrCb === "string" ? (encodingOrCb as BufferEncoding) : undefined;
            pushChunk(chunks, chunk, enc);
          }

          let body = Buffer.concat(chunks);
          const encodingHeader = (headers["content-encoding"] || headers["Content-Encoding"] || res.getHeader("content-encoding") || res.getHeader("Content-Encoding")) as string | string[] | undefined;
          const encoding = Array.isArray(encodingHeader) ? encodingHeader[0] : encodingHeader;
          if (encoding) {
            try {
              if (encoding.includes("br")) {
                body = zlib.brotliDecompressSync(body);
              } else if (encoding.includes("gzip")) {
                body = zlib.gunzipSync(body);
              } else if (encoding.includes("deflate")) {
                body = zlib.inflateSync(body);
              }
            } catch (_e) {}
          }

          let content = body.toString("utf8");

          if (contentType === "html") {
            content = transformHtml(content, maps);
            content = transformTextInHtml(content, maps.textKey);
            content = content.replace(/<\/head>/i, `${routeScript}${textScript}</head>`);
          } else if (contentType === "css") {
            content = transformCss(content, maps);
          } else if (contentType === "js") {
            content = transformJs(content, maps);
          }

          const transformedBody = Buffer.from(content, "utf8");

          headers["cache-control"] = "no-store, no-cache, must-revalidate";
          headers.pragma = "no-cache";

          headers["content-length"] = transformedBody.length;
          delete headers["transfer-encoding"];
          delete headers["content-encoding"];
          delete headers["Content-Encoding"];

          originalWriteHead(statusCode, headers);
          originalEnd(transformedBody);

          const callback = typeof chunk === "function" ? chunk : typeof encodingOrCb === "function" ? encodingOrCb : cb;
          if (typeof callback === "function") callback();

          return res;
        }

        return originalEnd(chunk, encodingOrCb, cb);
      };

      next();
    };

    app.use(transformMiddleware);
    app.use(handler);
  } else {
    app.use(handler);
  }
  app.listen({ port, host: "0.0.0.0" }, (err, addr) => {
    if (err) {
      console.error("Server failed to start:", err);
      process.exit(1);
    }
    console.log("Server listening on %s", addr);
  });
}

process.env.FIRST = process.env.FIRST || "true";
await Start();
