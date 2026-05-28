import { createMiddleware } from 'hono/factory';

import type { Env } from '../env';
import { isOidcAdminAuthConfigured, verifyOidcAdminToken } from '../auth/oidc';
import { AppError } from './errors';

function readBearerToken(authHeader: string | undefined | null): string | null {
  if (!authHeader) return null;
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  return match?.[1] ?? null;
}

function hasAnyAdminAuthConfigured(env: Env): boolean {
  return Boolean(env.ADMIN_TOKEN) || isOidcAdminAuthConfigured(env);
}

export function hasValidAdminTokenRequest(input: {
  env: Pick<Env, 'ADMIN_TOKEN'>;
  req: { header(name: string): string | undefined };
}): boolean {
  const token = input.env.ADMIN_TOKEN;
  if (!token) return false;
  return readBearerToken(input.req.header('authorization')) === token;
}

export async function hasValidAdminRequest(input: {
  env: Env;
  req: { header(name: string): string | undefined };
}): Promise<boolean> {
  if (hasValidAdminTokenRequest(input)) return true;

  const bearer = readBearerToken(input.req.header('authorization'));
  if (!bearer) return false;

  return verifyOidcAdminToken(bearer, input.env);
}

export async function hasValidAdminHttpRequest(request: Request, env: Env): Promise<boolean> {
  return hasValidAdminRequest({
    env,
    req: {
      header(name: string) {
        return request.headers.get(name) ?? undefined;
      },
    },
  });
}

export const requireAdmin = createMiddleware<{ Bindings: Env }>(async (c, next) => {
  if (!hasAnyAdminAuthConfigured(c.env)) {
    throw new AppError(500, 'INTERNAL', 'Admin auth not configured');
  }

  if (!(await hasValidAdminRequest(c))) {
    throw new AppError(401, 'UNAUTHORIZED', 'Unauthorized');
  }

  await next();
});
