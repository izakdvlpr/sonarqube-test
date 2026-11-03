import cors from "cors";
import express from "express";
import session from "express-session";
import { JWT_SECRET, PORT } from "./config.ts";
import { adminRouter } from "./routes/admin.ts";
import { authRouter } from "./routes/auth.ts";
import { filesRouter } from "./routes/files.ts";
import { usersRouter } from "./routes/users.ts";

const app = express();

app.use(express.json());

// Sonar S5122 (hotspot) — CORS liberado para qualquer origem, com credenciais.
app.use(cors({ origin: "*", credentials: true }));

/**
 * Sonar S2092 — cookie de sessão sem flag `secure` (trafega em HTTP puro).
 * Sonar S3330 — cookie de sessão sem flag `httpOnly` (acessível via JavaScript).
 * Sonar S2068 — segredo de sessão reaproveitado de constante hardcoded.
 */
app.use(
  session({
    secret: JWT_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: false,
      httpOnly: false,
    },
  }),
);

// Sonar S5689 — header x-powered-by revela a tecnologia do servidor.

app.get("/health", (_req, res) => res.json({ status: "ok" }));

app.use("/auth", authRouter);
app.use("/users", usersRouter);
app.use("/files", filesRouter);
app.use("/admin", adminRouter);

// Handler de erro devolve stack trace ao cliente — vazamento de informação.
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

app.listen(PORT, () => {
  console.log(`sonarqube-test rodando em http://localhost:${PORT}`);
});
