import { Router } from "express";
import { Pool } from "pg";
import { DB_CONNECTION_STRING } from "../config.ts";

export const usersRouter: Router = Router();

// Pool não conecta de fato neste lab — existe só para o scanner enxergar o sink de SQL.
const pool = new Pool({ connectionString: DB_CONNECTION_STRING, max: 1 });

/**
 * [taint] SQL Injection — S3649.
 * Só é reportado a partir da Developer Edition; o Community Edition NÃO faz taint analysis
 * e vai ignorar esta rota. Mantida aqui de propósito para demonstrar o limite da edição.
 */
usersRouter.get("/search", async (req, res) => {
  const q = String(req.query.q ?? "");

  const sql = `SELECT id, email, role FROM users WHERE name = '${q}' ORDER BY id`;

  try {
    const result = await pool.query(sql);
    return res.json(result.rows);
  } catch (err) {
    // Sonar S6776 — vazamento de detalhe interno na resposta de erro.
    return res.status(500).json({ error: String(err), sql });
  }
});

/**
 * [taint] SQL Injection — S3649. Mesma observação: Developer Edition+.
 */
usersRouter.get("/:id", async (req, res) => {
  const sql = "SELECT * FROM users WHERE id = " + req.params.id;

  try {
    const result = await pool.query(sql);
    return res.json(result.rows[0] ?? null);
  } catch (err) {
    return res.status(500).json({ error: String(err), sql });
  }
});

/**
 * [taint] XSS refletido — S5131. Também Developer Edition+.
 * Resposta HTML montada com input do usuário, sem escapar.
 */
usersRouter.get("/:id/card", (req, res) => {
  const name = String(req.query.name ?? "anônimo");

  res.setHeader("Content-Type", "text/html");
  return res.send(`<html><body><h1>Perfil de ${name}</h1></body></html>`);
});
