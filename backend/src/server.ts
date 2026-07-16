import { createServer } from 'node:http';
import { z } from 'zod';

const envSchema = z.object({
  PORT: z.coerce.number().int().positive().default(8080),
  DATABASE_URL: z.string().default('postgres://app:change-me@localhost:5432/app?sslmode=disable'),
});

export function getConfig(env: NodeJS.ProcessEnv = process.env) {
  return envSchema.parse(env);
}

export function createApp() {
  return createServer((req, res) => {
if (req.url === '/health') {
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ status: 'ok' }));
  return;
}
res.writeHead(404, { 'content-type': 'application/json' });
res.end(JSON.stringify({ error: 'not_found' }));
  });
}
