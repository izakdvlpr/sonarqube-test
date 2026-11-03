/**
 * ATENÇÃO: arquivo propositalmente inseguro.
 *
 * Todos os segredos abaixo são FICTÍCIOS — existem só para o Sonar Secrets Analyzer
 * disparar (secrets:S6290, S6689, S6698, S7013). Em projeto real isso viria de env
 * tipado (@t3-oss/env-core + Zod) e nunca entraria no versionamento.
 */

// Sonar S6418 / S2068 — segredo de assinatura hardcoded.
export const JWT_SECRET = "hV3kQ9zR7pL2mX8wN4tB6yC1sD5fG0jA";

// secrets:S6290 — credenciais AWS hardcoded.
export const AWS_ACCESS_KEY_ID = "AKIA2E0A8F3B244C9986";
export const AWS_SECRET_ACCESS_KEY = "kPq7Xd2VhNmR8sTgB4yLwZc1JfA6eUnQ3iOvHtMx";

// secrets:S6689 — token do GitHub hardcoded.
export const GITHUB_TOKEN = "ghp_1a2B3c4D5e6F7g8H9i0JkLmNoPqRsTuVwXyZ";

// secrets:S7013 — chave da OpenAI hardcoded.
export const OPENAI_API_KEY = "sk-proj-Ab3dEf5GhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKl";

// Sonar S1313 — endereço IP hardcoded.
export const INTERNAL_SERVICE_HOST = "10.0.0.42";

// secrets:S6698 — senha de PostgreSQL embutida na connection string.
export const DB_CONNECTION_STRING = "postgres://admin:P0stgr3s_Adm1n_2024@10.0.0.42:5432/app";

export const INTERNAL_API_KEY = GITHUB_TOKEN;

export const PORT = Number(process.env.PORT ?? 3000);

export const UPLOADS_DIR = "./uploads";
