import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const configuration = readFileSync(
  fileURLToPath(new URL('../../nginx.conf', import.meta.url)),
  'utf8',
);
const serverHeaders = configuration.split('location /api/ {')[0];
const assets = configuration.match(/location \/assets\/ \{([\s\S]*?)\n    \}/)?.[1] ?? '';

describe('Nginx browser security policy', () => {
  it.each([
    'Content-Security-Policy',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'Referrer-Policy',
    'Permissions-Policy',
    'Cross-Origin-Resource-Policy',
  ])('defines %s at both server and assets scopes', (header) => {
    expect(serverHeaders).toContain('add_header ' + header + ' ');
    expect(assets).toContain('add_header ' + header + ' ');
  });

  it('prevents caching index.html without weakening hashed asset caching', () => {
    expect(configuration).toMatch(/location = \/index\.html \{\s*expires -1;/);
    expect(assets).toMatch(/expires 1y;/);
    expect(assets).toContain('public, immutable');
    expect(configuration).toContain('try_files $uri $uri/ /index.html;');
  });

  it('uses an SPA-compatible CSP that blocks framing and objects', () => {
    expect(serverHeaders).toContain("script-src 'self'");
    expect(serverHeaders).toContain("frame-ancestors 'none'");
    expect(serverHeaders).toContain("object-src 'none'");
  });
});
