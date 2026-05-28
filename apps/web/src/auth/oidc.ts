import { ADMIN_CALLBACK_PATH, ADMIN_PATH } from '../app/adminPaths';

const OIDC_STATE_KEY = 'uptimer_oidc_state_v1';
const OIDC_VERIFIER_KEY = 'uptimer_oidc_code_verifier_v1';
const OIDC_RETURN_TO_KEY = 'uptimer_oidc_return_to_v1';

type OidcTokenResponse = {
  access_token?: unknown;
  token_type?: unknown;
  expires_in?: unknown;
};

function normalizeIssuer(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim().replace(/\/+$/, '');
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

function configuredIssuer(): string | null {
  return normalizeIssuer(import.meta.env.VITE_AUTH_ISSUER);
}

function configuredClientId(): string | null {
  const value = import.meta.env.VITE_AUTH_CLIENT_ID;
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

function configuredResource(): string | null {
  const value = import.meta.env.VITE_AUTH_RESOURCE;
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

function configuredScope(): string {
  const value = import.meta.env.VITE_AUTH_SCOPE;
  return typeof value === 'string' && value.trim()
    ? value.trim()
    : 'openid profile email uptimer.admin';
}

function configuredRedirectPath(): string {
  const value = import.meta.env.VITE_AUTH_REDIRECT_PATH;
  if (typeof value !== 'string' || !value.trim()) return ADMIN_CALLBACK_PATH;
  const trimmed = value.trim();
  return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}

function redirectUri(): string {
  return new URL(configuredRedirectPath(), window.location.origin).toString();
}

function randomBase64Url(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]!);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function codeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return bytesToBase64Url(new Uint8Array(digest));
}

function sanitizeReturnTo(value: string | undefined): string {
  if (!value || !value.startsWith('/') || value.startsWith('//')) return ADMIN_PATH;
  try {
    const parsed = new URL(value, window.location.origin);
    if (parsed.origin !== window.location.origin) return ADMIN_PATH;
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return ADMIN_PATH;
  }
}

export function isOidcLoginConfigured(): boolean {
  return Boolean(configuredIssuer() && configuredClientId());
}

export async function startOidcLogin(returnTo: string): Promise<void> {
  const issuer = configuredIssuer();
  const clientId = configuredClientId();
  if (!issuer || !clientId) {
    throw new Error('OIDC login is not configured');
  }

  const state = randomBase64Url(32);
  const verifier = randomBase64Url(64);
  const challenge = await codeChallenge(verifier);

  sessionStorage.setItem(OIDC_STATE_KEY, state);
  sessionStorage.setItem(OIDC_VERIFIER_KEY, verifier);
  sessionStorage.setItem(OIDC_RETURN_TO_KEY, sanitizeReturnTo(returnTo));

  const url = new URL(`${issuer}/oauth2/authorize`);
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri());
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', configuredScope());
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('state', state);

  const resource = configuredResource();
  if (resource) {
    url.searchParams.set('resource', resource);
  }

  window.location.assign(url.toString());
}

function clearPendingLogin(): void {
  sessionStorage.removeItem(OIDC_STATE_KEY);
  sessionStorage.removeItem(OIDC_VERIFIER_KEY);
  sessionStorage.removeItem(OIDC_RETURN_TO_KEY);
}

function readTokenResponse(value: OidcTokenResponse): string {
  if (typeof value.access_token !== 'string' || !value.access_token.trim()) {
    throw new Error('Token response did not include an access token');
  }
  if (value.token_type && String(value.token_type).toLowerCase() !== 'bearer') {
    throw new Error('Token response used an unsupported token type');
  }
  return value.access_token;
}

export async function finishOidcLogin(callbackUrl: string): Promise<{
  accessToken: string;
  returnTo: string;
}> {
  const issuer = configuredIssuer();
  const clientId = configuredClientId();
  if (!issuer || !clientId) {
    throw new Error('OIDC login is not configured');
  }

  const url = new URL(callbackUrl);
  const error = url.searchParams.get('error');
  if (error) {
    throw new Error(error);
  }

  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const expectedState = sessionStorage.getItem(OIDC_STATE_KEY);
  const verifier = sessionStorage.getItem(OIDC_VERIFIER_KEY);
  const returnTo = sanitizeReturnTo(sessionStorage.getItem(OIDC_RETURN_TO_KEY) ?? undefined);

  if (!code || !state || !expectedState || state !== expectedState || !verifier) {
    clearPendingLogin();
    throw new Error('Invalid OIDC callback');
  }

  const body = new URLSearchParams();
  body.set('grant_type', 'authorization_code');
  body.set('code', code);
  body.set('redirect_uri', redirectUri());
  body.set('client_id', clientId);
  body.set('code_verifier', verifier);

  const resource = configuredResource();
  if (resource) {
    body.set('resource', resource);
  }

  const res = await fetch(`${issuer}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });

  if (!res.ok) {
    clearPendingLogin();
    throw new Error(`Token exchange failed (${res.status})`);
  }

  const payload = (await res.json()) as OidcTokenResponse;
  const accessToken = readTokenResponse(payload);
  clearPendingLogin();

  return { accessToken, returnTo };
}
