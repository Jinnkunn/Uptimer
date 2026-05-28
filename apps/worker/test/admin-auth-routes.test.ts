import { describe, expect, it, vi } from 'vitest';

vi.mock('../src/snapshots', () => ({
  refreshPublicHomepageSnapshotIfNeeded: vi.fn().mockResolvedValue(false),
}));
vi.mock('../src/monitor/tcp', () => ({
  runTcpCheck: vi.fn(),
}));

import type { Env } from '../src/env';
import { adminRoutes } from '../src/routes/admin';

describe('admin auth routes', () => {
  it('returns the JSON error contract when auth is missing', async () => {
    const res = await adminRoutes.fetch(
      new Request('https://uptimer.example.test/auth/verify'),
      {
        ADMIN_TOKEN: 'secret-token',
        ADMIN_RATE_LIMIT_MAX: '60',
        ADMIN_RATE_LIMIT_WINDOW_SEC: '60',
      } as Env,
      {} as ExecutionContext,
    );

    expect(res.status).toBe(401);
    await expect(res.json()).resolves.toEqual({
      error: { code: 'UNAUTHORIZED', message: 'Unauthorized' },
    });
  });
});
