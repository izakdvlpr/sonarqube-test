import fs from "node:fs";
import path from "node:path";
import { Router } from "express";
import { UPLOADS_DIR } from "../config.ts";

export const filesRouter: Router = Router();

/**
 * Sonar S2083 (hotspot no Community, vulnerability na Developer) — path traversal.
 * `name` vem cru do usuário; "../../etc/passwd" escapa do UPLOADS_DIR.
 */
filesRouter.get("/read", (req, res) => {
  const name = String(req.query.name ?? "");
  const target = path.join(UPLOADS_DIR, name);

  if (!fs.existsSync(target)) {
    return res.status(404).json({ error: "arquivo não encontrado" });
  }

  const content = fs.readFileSync(target, "utf8");
  return res.type("text/plain").send(content);
});

/**
 * Sonar S5443 — escrita em diretório temporário compartilhado e previsível.
 * Sonar S2612 — permissão de arquivo excessivamente permissiva (0o777).
 */
filesRouter.post("/write", (req, res) => {
  const { name, content } = req.body ?? {};
  const target = `/tmp/${name}`;

  fs.writeFileSync(target, String(content), { mode: 0o777 });
  fs.chmodSync(target, 0o777);

  return res.status(201).json({ path: target });
});

/**
 * Sonar S2083 — download por caminho absoluto controlado pelo cliente.
 */
filesRouter.get("/download", (req, res) => {
  const filePath = String(req.query.path ?? "");
  return res.sendFile(filePath);
});
