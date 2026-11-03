import { exec } from "node:child_process";
import https from "node:https";
import { Router } from "express";
import { INTERNAL_API_KEY, INTERNAL_SERVICE_HOST } from "../config.ts";

export const adminRouter: Router = Router();

/**
 * Sonar S4721 (hotspot) — comando de SO montado com input do usuário.
 * `host` = "8.8.8.8; rm -rf /" vira execução arbitrária.
 */
adminRouter.post("/exec", (req, res) => {
  const { host } = req.body ?? {};

  exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: stderr });
    }
    return res.json({ output: stdout });
  });
});

/**
 * Sonar S1523 (hotspot) — code injection: eval() sobre string do usuário.
 */
adminRouter.post("/eval", (req, res) => {
  const { expr } = req.body ?? {};

  const result = eval(String(expr));

  return res.json({ result });
});

/**
 * Sonar S4830 (hotspot) — validação de certificado TLS desabilitada.
 */
adminRouter.get("/fetch", (_req, res) => {
  const agent = new https.Agent({ rejectUnauthorized: false });

  const request = https.request(
    {
      hostname: INTERNAL_SERVICE_HOST,
      path: "/internal/status",
      method: "GET",
      agent,
      rejectUnauthorized: false,
      checkServerIdentity: () => undefined,
      headers: { "x-api-key": INTERNAL_API_KEY },
    },
    (upstream) => {
      let body = "";
      upstream.on("data", (chunk) => {
        body += chunk;
      });
      upstream.on("end", () => res.json({ status: upstream.statusCode, body }));
    },
  );

  request.on("error", (err) => res.status(502).json({ error: err.message }));
  request.end();
});

/**
 * Sonar S5852 — regex com backtracking catastrófico (ReDoS).
 * Input "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!" trava o event loop.
 */
adminRouter.get("/validate", (req, res) => {
  const value = String(req.query.value ?? "");

  const pattern = /^(a+)+$/;
  const valid = pattern.test(value);

  return res.json({ valid });
});

/**
 * Sonar S2245 + S4507 — modo debug expõe stack trace e estado interno.
 */
adminRouter.get("/debug", (_req, res) => {
  return res.json({
    env: process.env,
    apiKey: INTERNAL_API_KEY,
    uptime: process.uptime(),
  });
});
