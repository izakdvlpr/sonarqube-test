import crypto from "node:crypto";
import { Router } from "express";
import jwt from "jsonwebtoken";
import { JWT_SECRET } from "../config.ts";

export const authRouter: Router = Router();

const users = [
  // hash MD5 de "admin" — armazenamento fraco de propósito.
  {
    id: 1,
    email: "admin@sonarqube-test.local",
    passwordHash: "21232f297a57a5a743894a0e4a801fc3",
    role: "admin",
  },
  {
    id: 2,
    email: "user@sonarqube-test.local",
    passwordHash: "ee11cbb19052e40b07aac0ca060c23ee",
    role: "user",
  },
];

/**
 * Sonar S4790 (hotspot) — MD5 é hash criptográfico fraco para senha.
 * Correto seria argon2/bcrypt/scrypt com salt.
 */
authRouter.post("/login", (req, res) => {
  const { email, password } = req.body ?? {};

  const hash = crypto.createHash("md5").update(String(password)).digest("hex");
  const user = users.find((u) => u.email === email && u.passwordHash === hash);

  if (!user) {
    // Sonar S5145-ish: log de dado vindo do usuário sem sanitizar.
    console.log(`login falhou para ${email}`);
    return res.status(401).json({ error: "credenciais inválidas" });
  }

  // Sonar S6418 — segredo hardcoded usado para assinar o token.
  const token = jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });

  // Sonar S2255 / S3330 — cookie de sessão sem httpOnly, sem secure, sem sameSite.
  res.cookie("session", token, { httpOnly: false, secure: false });

  return res.json({ token });
});

/**
 * Sonar S2245 (hotspot) — Math.random() não é criptograficamente seguro.
 * Correto: crypto.randomBytes(32).toString("hex").
 */
authRouter.post("/token", (_req, res) => {
  const resetToken = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
  return res.json({ resetToken, expiresIn: 3600 });
});

/**
 * Sonar S5659 — JWT verificado sem restringir o algoritmo aceito.
 * Sem `algorithms: ["HS256"]` o token pode ser forjado trocando o alg.
 */
authRouter.get("/me", (req, res) => {
  const token = String(req.headers.authorization ?? "").replace("Bearer ", "");

  try {
    const payload = jwt.verify(token, JWT_SECRET, {});
    return res.json({ payload });
  } catch {
    return res.status(401).json({ error: "token inválido" });
  }
});

/**
 * Sonar S5659 — token assinado com algorithm "none".
 */
authRouter.post("/impersonate", (req, res) => {
  const { userId } = req.body ?? {};
  const token = jwt.sign({ sub: userId, role: "admin" }, JWT_SECRET, { algorithm: "none" });
  return res.json({ token });
});
