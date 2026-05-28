import { afterEach, describe, expect, it, vi } from 'vitest';

import { clearOidcJwksCacheForTests } from '../src/auth/oidc';
import { requireAdmin } from '../src/middleware/auth';
import { AppError } from '../src/middleware/errors';

function makeContext(options: {
  token: string | undefined;
  authorization: string | undefined;
  oidc?: Record<string, string>;
}): unknown {
  return {
    env: { ADMIN_TOKEN: options.token, ...options.oidc },
    req: {
      header(name: string) {
        if (name.toLowerCase() === 'authorization') return options.authorization;
        return undefined;
      },
    },
  };
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]!);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function jsonToBase64Url(value: unknown): string {
  return bytesToBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}

async function createSignedJwt(claims: Record<string, unknown>): Promise<{
  token: string;
  jwk: JsonWebKey;
}> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );
  const jwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  jwk.kid = 'test-kid';
  jwk.alg = 'RS256';
  jwk.use = 'sig';

  const header = jsonToBase64Url({ alg: 'RS256', kid: jwk.kid, typ: 'at+jwt' });
  const payload = jsonToBase64Url(claims);
  const signingInput = `${header}.${payload}`;
  const signature = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    keyPair.privateKey,
    new TextEncoder().encode(signingInput),
  );

  return {
    token: `${signingInput}.${bytesToBase64Url(new Uint8Array(signature))}`,
    jwk,
  };
}

describe('middleware/auth', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    clearOidcJwksCacheForTests();
  });

  it('allows requests with matching bearer token', async () => {
    const next = vi.fn(async () => undefined);
    const c = makeContext({
      token: 'secret-token',
      authorization: 'Bearer secret-token',
    });

    await requireAdmin(c as never, next);
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('allows requests with a valid OIDC admin access token', async () => {
    clearOidcJwksCacheForTests();
    const now = Math.floor(Date.now() / 1000);
    const { token, jwk } = await createSignedJwt({
      iss: 'https://auth.example.test',
      sub: 'user-1',
      org: 'org-1',
      aud: 'urn:test:uptimer',
      exp: now + 300,
      iat: now,
      scope: 'openid uptimer.admin',
      client_id: 'uptimer-web',
    });
    const fetchMock = vi.fn(async () =>
      Response.json({
        keys: [jwk],
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const next = vi.fn(async () => undefined);
    const c = makeContext({
      token: undefined,
      authorization: `Bearer ${token}`,
      oidc: {
        UPTIMER_AUTH_ISSUER: 'https://auth.example.test',
        UPTIMER_AUTH_JWKS_URL: 'https://auth.example.test/oauth2/jwks.json',
        UPTIMER_AUTH_AUDIENCE: 'urn:test:uptimer',
        UPTIMER_AUTH_REQUIRED_SCOPE: 'uptimer.admin',
        UPTIMER_AUTH_ALLOWED_CLIENT_IDS: 'uptimer-web',
        UPTIMER_AUTH_ALLOWED_SUBS: 'user-1',
      },
    });

    await requireAdmin(c as never, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('rejects an OIDC token without an allowed subject or organization', async () => {
    clearOidcJwksCacheForTests();
    const now = Math.floor(Date.now() / 1000);
    const { token, jwk } = await createSignedJwt({
      iss: 'https://auth-no-allowlist.example.test',
      sub: 'user-2',
      org: 'org-2',
      aud: 'urn:test:uptimer',
      exp: now + 300,
      iat: now,
      scope: 'openid uptimer.admin',
      client_id: 'uptimer-web',
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => Response.json({ keys: [jwk] })),
    );

    const next = vi.fn(async () => undefined);
    const c = makeContext({
      token: undefined,
      authorization: `Bearer ${token}`,
      oidc: {
        UPTIMER_AUTH_ISSUER: 'https://auth-no-allowlist.example.test',
        UPTIMER_AUTH_JWKS_URL: 'https://auth-no-allowlist.example.test/oauth2/jwks.json',
        UPTIMER_AUTH_AUDIENCE: 'urn:test:uptimer',
        UPTIMER_AUTH_REQUIRED_SCOPE: 'uptimer.admin',
        UPTIMER_AUTH_ALLOWED_CLIENT_IDS: 'uptimer-web',
      },
    });

    await expect(requireAdmin(c as never, next)).rejects.toMatchObject({
      status: 401,
      code: 'UNAUTHORIZED',
    } satisfies Partial<AppError>);
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects requests when auth header is missing/invalid', async () => {
    const next = vi.fn(async () => undefined);
    const missingHeader = makeContext({
      token: 'secret-token',
      authorization: undefined,
    });

    await expect(requireAdmin(missingHeader as never, next)).rejects.toMatchObject({
      status: 401,
      code: 'UNAUTHORIZED',
    } satisfies Partial<AppError>);
    expect(next).not.toHaveBeenCalled();

    const wrongToken = makeContext({
      token: 'secret-token',
      authorization: 'Bearer wrong',
    });
    await expect(requireAdmin(wrongToken as never, next)).rejects.toMatchObject({
      status: 401,
      code: 'UNAUTHORIZED',
    } satisfies Partial<AppError>);
    expect(next).not.toHaveBeenCalled();
  });

  it('returns internal error when admin token is not configured', async () => {
    const c = makeContext({
      token: undefined,
      authorization: 'Bearer anything',
    });

    await expect(requireAdmin(c as never, vi.fn())).rejects.toMatchObject({
      status: 500,
      code: 'INTERNAL',
    } satisfies Partial<AppError>);
  });
});
