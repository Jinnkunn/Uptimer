import type { Env } from '../env';

type OidcEnv = Pick<
  Env,
  | 'UPTIMER_AUTH_ISSUER'
  | 'UPTIMER_AUTH_JWKS_URL'
  | 'UPTIMER_AUTH_AUDIENCES'
  | 'UPTIMER_AUTH_AUDIENCE'
  | 'UPTIMER_AUTH_REQUIRED_SCOPES'
  | 'UPTIMER_AUTH_REQUIRED_SCOPE'
  | 'UPTIMER_AUTH_ALLOWED_CLIENT_IDS'
  | 'UPTIMER_AUTH_ALLOWED_SUBS'
  | 'UPTIMER_AUTH_ALLOWED_ORGS'
  | 'UPTIMER_AUTH_ALLOW_ANY_SUBJECT'
  | 'UPTIMER_AUTH_CLOCK_SKEW_SECONDS'
>;

type JwtHeader = {
  alg?: unknown;
  kid?: unknown;
  typ?: unknown;
};

type JwtClaims = {
  iss?: unknown;
  sub?: unknown;
  aud?: unknown;
  exp?: unknown;
  nbf?: unknown;
  iat?: unknown;
  scope?: unknown;
  client_id?: unknown;
  org?: unknown;
};

type JwksCacheEntry = {
  expiresAt: number;
  keys: Map<string, JwkWithKid>;
};

type JwkWithKid = JsonWebKey & {
  kid?: string;
  alg?: string;
  use?: string;
};

type OidcAdminConfig = {
  issuer: string;
  jwksUrl: string;
  audiences: string[];
  requiredScopes: string[];
  allowedClientIds: string[];
  allowedSubjects: string[];
  allowedOrganizations: string[];
  allowAnySubject: boolean;
  clockSkewSeconds: number;
};

const DEFAULT_REQUIRED_SCOPE = 'uptimer.admin';
const DEFAULT_CLOCK_SKEW_SECONDS = 60;
const JWKS_CACHE_TTL_MS = 5 * 60 * 1000;
const MAX_TOKEN_BYTES = 16 * 1024;
const textEncoder = new TextEncoder();
const jwksCache = new Map<string, JwksCacheEntry>();

function splitList(value: string | undefined, separator: RegExp = /[\s,]+/): string[] {
  if (!value) return [];
  return value
    .split(separator)
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}

function parseTruthy(value: string | undefined): boolean {
  return ['1', 'true', 'yes', 'on'].includes((value ?? '').trim().toLowerCase());
}

function parsePositiveInteger(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 0) return fallback;
  return parsed;
}

function normalizeIssuer(value: string | undefined): string | null {
  const trimmed = value?.trim().replace(/\/+$/, '') ?? '';
  if (!trimmed) return null;
  try {
    const url = new URL(trimmed);
    if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
      return null;
    }
    return url.toString().replace(/\/+$/, '');
  } catch {
    return null;
  }
}

function resolveOidcAdminConfig(env: OidcEnv): OidcAdminConfig | null {
  const issuer = normalizeIssuer(env.UPTIMER_AUTH_ISSUER);
  const audiences = splitList(env.UPTIMER_AUTH_AUDIENCES ?? env.UPTIMER_AUTH_AUDIENCE);
  if (!issuer || audiences.length === 0) return null;

  const configuredJwksUrl = env.UPTIMER_AUTH_JWKS_URL?.trim();
  const jwksUrl =
    configuredJwksUrl && configuredJwksUrl.length > 0
      ? configuredJwksUrl
      : `${issuer}/oauth2/jwks.json`;

  return {
    issuer,
    jwksUrl,
    audiences,
    requiredScopes: splitList(env.UPTIMER_AUTH_REQUIRED_SCOPES ?? env.UPTIMER_AUTH_REQUIRED_SCOPE)
      .length
      ? splitList(env.UPTIMER_AUTH_REQUIRED_SCOPES ?? env.UPTIMER_AUTH_REQUIRED_SCOPE)
      : [DEFAULT_REQUIRED_SCOPE],
    allowedClientIds: splitList(env.UPTIMER_AUTH_ALLOWED_CLIENT_IDS),
    allowedSubjects: splitList(env.UPTIMER_AUTH_ALLOWED_SUBS),
    allowedOrganizations: splitList(env.UPTIMER_AUTH_ALLOWED_ORGS),
    allowAnySubject: parseTruthy(env.UPTIMER_AUTH_ALLOW_ANY_SUBJECT),
    clockSkewSeconds: parsePositiveInteger(
      env.UPTIMER_AUTH_CLOCK_SKEW_SECONDS,
      DEFAULT_CLOCK_SKEW_SECONDS,
    ),
  };
}

export function isOidcAdminAuthConfigured(env: OidcEnv): boolean {
  return resolveOidcAdminConfig(env) !== null;
}

function base64UrlToBytes(value: string): Uint8Array {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function decodeJsonPart<T>(value: string): T {
  const json = new TextDecoder().decode(base64UrlToBytes(value));
  return JSON.parse(json) as T;
}

function parseJwt(
  token: string,
): { header: JwtHeader; claims: JwtClaims; signature: Uint8Array; signingInput: string } | null {
  if (token.length === 0 || token.length > MAX_TOKEN_BYTES) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  try {
    return {
      header: decodeJsonPart<JwtHeader>(parts[0]!),
      claims: decodeJsonPart<JwtClaims>(parts[1]!),
      signature: base64UrlToBytes(parts[2]!),
      signingInput: `${parts[0]}.${parts[1]}`,
    };
  } catch {
    return null;
  }
}

function isJwks(value: unknown): value is { keys: JsonWebKey[] } {
  if (!value || typeof value !== 'object') return false;
  const keys = (value as { keys?: unknown }).keys;
  return Array.isArray(keys);
}

async function loadJwks(jwksUrl: string, forceRefresh = false): Promise<Map<string, JwkWithKid>> {
  const now = Date.now();
  const cached = jwksCache.get(jwksUrl);
  if (!forceRefresh && cached && cached.expiresAt > now) {
    return cached.keys;
  }

  const res = await fetch(jwksUrl, { cache: 'no-store' });
  if (!res.ok) {
    throw new Error('JWKS fetch failed');
  }
  const data = (await res.json()) as unknown;
  if (!isJwks(data)) {
    throw new Error('Invalid JWKS');
  }

  const keys = new Map<string, JwkWithKid>();
  for (const key of data.keys as JwkWithKid[]) {
    if (
      key.kty === 'RSA' &&
      key.kid &&
      typeof key.kid === 'string' &&
      (!key.alg || key.alg === 'RS256') &&
      (!key.use || key.use === 'sig')
    ) {
      keys.set(key.kid, key);
    }
  }

  jwksCache.set(jwksUrl, {
    expiresAt: now + JWKS_CACHE_TTL_MS,
    keys,
  });
  return keys;
}

async function verifySignature(input: {
  jwk: JwkWithKid;
  signingInput: string;
  signature: Uint8Array;
}): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    'jwk',
    input.jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  );

  return crypto.subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    key,
    toArrayBuffer(input.signature),
    toArrayBuffer(textEncoder.encode(input.signingInput)),
  );
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const out = new Uint8Array(bytes.byteLength);
  out.set(bytes);
  return out.buffer;
}

function audiencesFromClaim(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === 'string');
  }
  return [];
}

function scopeSet(value: unknown): Set<string> {
  if (typeof value !== 'string') return new Set();
  return new Set(splitList(value, /\s+/));
}

function claimsAreAllowed(claims: JwtClaims, config: OidcAdminConfig, nowSeconds: number): boolean {
  if (claims.iss !== config.issuer) return false;
  if (typeof claims.exp !== 'number' || claims.exp + config.clockSkewSeconds < nowSeconds) {
    return false;
  }
  if (typeof claims.nbf === 'number' && claims.nbf - config.clockSkewSeconds > nowSeconds) {
    return false;
  }
  if (typeof claims.iat === 'number' && claims.iat - config.clockSkewSeconds > nowSeconds) {
    return false;
  }

  const tokenAudiences = audiencesFromClaim(claims.aud);
  if (!tokenAudiences.some((audience) => config.audiences.includes(audience))) {
    return false;
  }

  const scopes = scopeSet(claims.scope);
  if (!config.requiredScopes.every((scope) => scopes.has(scope))) {
    return false;
  }

  if (
    config.allowedClientIds.length > 0 &&
    (typeof claims.client_id !== 'string' || !config.allowedClientIds.includes(claims.client_id))
  ) {
    return false;
  }

  if (config.allowAnySubject) return true;

  const subjectAllowed =
    typeof claims.sub === 'string' && config.allowedSubjects.includes(claims.sub);
  const orgAllowed =
    typeof claims.org === 'string' && config.allowedOrganizations.includes(claims.org);

  return subjectAllowed || orgAllowed;
}

export async function verifyOidcAdminToken(token: string, env: OidcEnv): Promise<boolean> {
  const config = resolveOidcAdminConfig(env);
  if (!config) return false;

  const parsed = parseJwt(token);
  if (!parsed) return false;

  const kid = typeof parsed.header.kid === 'string' ? parsed.header.kid : null;
  if (parsed.header.alg !== 'RS256' || !kid) return false;

  try {
    let keys = await loadJwks(config.jwksUrl);
    let jwk = keys.get(kid);
    if (!jwk) {
      keys = await loadJwks(config.jwksUrl, true);
      jwk = keys.get(kid);
    }
    if (!jwk) return false;

    const signatureOk = await verifySignature({
      jwk,
      signingInput: parsed.signingInput,
      signature: parsed.signature,
    });
    if (!signatureOk) return false;

    return claimsAreAllowed(parsed.claims, config, Math.floor(Date.now() / 1000));
  } catch {
    return false;
  }
}

export function clearOidcJwksCacheForTests(): void {
  jwksCache.clear();
}
