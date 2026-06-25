import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  checkSecurityHeaders,
  checkCookies,
  checkTLS,
  checkMixedContent,
  scoreReport,
  normalizeUrl,
  buildCertErrorReport,
} from './check.mjs';

test('証明書エラー：取得失敗で終わらせず TLS warn の最小レポートを返す', () => {
  const r = buildCertErrorReport({
    url: 'https://self-signed.badssl.com/',
    tls: { authorized: false, authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT' },
    reason: 'fetch failed',
  });
  assert.equal(r.tls.status, 'warn');
  assert.equal(r.headers.length, 5);
  assert.ok(r.headers.every((h) => h.status === 'warn'));
  assert.ok(r.summary.score < 50);
  assert.equal(r.summary.grade, 'D');
});

test('URL正規化：スキーム無しは https:// を補う', () => {
  assert.equal(normalizeUrl('github.com'), 'https://github.com');
  assert.equal(normalizeUrl('github.com/path?q=1'), 'https://github.com/path?q=1');
  assert.equal(normalizeUrl('  example.com  '), 'https://example.com');
  // すでに付いていれば変えない
  assert.equal(normalizeUrl('https://github.com'), 'https://github.com');
  assert.equal(normalizeUrl('http://example.com'), 'http://example.com');
});

test('ヘッダ：全部欠けていれば全 warn', () => {
  const r = checkSecurityHeaders({});
  assert.equal(r.length, 5);
  assert.ok(r.every((h) => h.status === 'warn'));
});

test('ヘッダ：値が揃っていれば ok / 悪い値は warn', () => {
  const r = checkSecurityHeaders({
    'content-security-policy': "default-src 'self'",
    'strict-transport-security': 'max-age=63072000',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
  });
  assert.ok(r.every((h) => h.status === 'ok'));

  const bad = checkSecurityHeaders({ 'x-content-type-options': 'sniff' });
  assert.equal(bad.find((h) => h.label === 'X-Content-Type-Options').status, 'warn');
});

test('ヘッダ回帰：HSTS max-age=0 は無効化なので warn（誤✅防止）', () => {
  const r = checkSecurityHeaders({ 'strict-transport-security': 'max-age=0' });
  assert.equal(r.find((h) => h.label.includes('HSTS')).status, 'warn');
  // 正の max-age は ok
  assert.equal(
    checkSecurityHeaders({ 'strict-transport-security': 'max-age=31536000' }).find((h) => h.label.includes('HSTS')).status,
    'ok',
  );
});

test('ヘッダ回帰：危険な CSP は存在しても warn（誤✅防止）', () => {
  const weak = checkSecurityHeaders({ 'content-security-policy': "default-src *; script-src 'unsafe-inline'" });
  assert.equal(weak.find((h) => h.label.includes('Content-Security')).status, 'warn');
  // 健全な CSP は ok / style-src の unsafe-inline は許容（過剰⚠️回避）
  const good = checkSecurityHeaders({ 'content-security-policy': "default-src 'self'; style-src 'self' 'unsafe-inline'" });
  assert.equal(good.find((h) => h.label.includes('Content-Security')).status, 'ok');
});

test('ヘッダ回帰：Referrer-Policy unsafe-url は warn', () => {
  assert.equal(
    checkSecurityHeaders({ 'referrer-policy': 'unsafe-url' }).find((h) => h.label.includes('Referrer')).status,
    'warn',
  );
  assert.equal(
    checkSecurityHeaders({ 'referrer-policy': 'no-referrer' }).find((h) => h.label.includes('Referrer')).status,
    'ok',
  );
});

test('Cookie回帰：値に secure/httponly を含むだけでは属性扱いしない（誤✅防止）', () => {
  const r = checkCookies(['prefs=secure_httponly_mode; Path=/']);
  assert.equal(r.items[0].secure, false);
  assert.equal(r.items[0].httpOnly, false);
  assert.deepEqual(r.items[0].missing, ['HttpOnly', 'Secure', 'SameSite']);
});

test('Cookie：フラグ不足を検出', () => {
  const r = checkCookies(['sid=abc; Path=/']);
  assert.equal(r.status, 'warn');
  assert.deepEqual(r.items[0].missing, ['HttpOnly', 'Secure', 'SameSite']);

  const good = checkCookies(['sid=abc; HttpOnly; Secure; SameSite=Lax']);
  assert.equal(good.status, 'ok');
});

test('Cookie回帰：SameSite=None は無防備なので不十分(warn)扱い（誤✅防止）', () => {
  const none = checkCookies(['sid=abc; HttpOnly; Secure; SameSite=None']);
  assert.equal(none.items[0].status, 'warn');
  assert.ok(none.items[0].missing.some((m) => m.includes('SameSite')));
  // Lax / Strict は守れているので ok
  assert.equal(checkCookies(['sid=abc; HttpOnly; Secure; SameSite=Strict']).items[0].status, 'ok');
});

test('Cookie：無ければ ok', () => {
  assert.equal(checkCookies([]).status, 'ok');
});

test('TLS：期限切れ・間近・有効', () => {
  assert.equal(checkTLS({ protocol: 'https:', authorized: true, daysToExpiry: -1, validTo: 'x' }).status, 'warn');
  assert.equal(checkTLS({ protocol: 'https:', authorized: true, daysToExpiry: 7, validTo: 'x' }).status, 'warn');
  assert.equal(checkTLS({ protocol: 'https:', authorized: true, daysToExpiry: 200 }).status, 'ok');
  assert.equal(checkTLS({ protocol: 'http:' }).status, 'warn');
});

test('TLS回帰：期限が読めない時は authorized===true でだけ ok・曖昧は warn（誤✅防止）', () => {
  // システム検証OK・期限だけ読めず → ok（透明に「期限取得できず」）
  assert.equal(checkTLS({ protocol: 'https:', authorized: true }).status, 'ok');
  // 検証が確定していない（authorized が true でない）→ warn に倒す
  assert.equal(checkTLS({ protocol: 'https:' }).status, 'warn');
  // 期限が NaN（壊れた日付）でも「NaN 日」で ok にしない
  assert.equal(checkTLS({ protocol: 'https:', authorized: true, daysToExpiry: NaN }).status, 'ok');
});

test('混在コンテンツ：HTTPS ページ内の http リソースを検出', () => {
  const html = '<img src="http://x.test/a.png"><script src="https://ok.test/b.js"></script>';
  const r = checkMixedContent(html, true);
  assert.equal(r.status, 'warn');
  assert.deepEqual(r.items, ['http://x.test/a.png']);

  assert.equal(checkMixedContent(html, false).status, 'ok');
});

test('混在回帰：<a href> ただのリンクは混在として誤検出しない', () => {
  const r = checkMixedContent('<a href="http://example.com">外部リンク</a>', true);
  assert.equal(r.status, 'ok');
  assert.deepEqual(r.items, []);
});

test('混在回帰：<link href> の CSS は属性順を問わず混在として検出', () => {
  assert.equal(checkMixedContent('<link rel="stylesheet" href="http://cdn.test/s.css">', true).status, 'warn');
  assert.equal(checkMixedContent('<link href="http://cdn.test/s.css" rel="stylesheet">', true).status, 'warn');
});

test('スコア回帰：Cookie は何個でも1項目として数える（点が偏らない）', () => {
  const report = {
    headers: [{ status: 'ok' }],
    cookies: { status: 'warn', items: [{ status: 'warn' }, { status: 'warn' }, { status: 'warn' }] },
    tls: { status: 'ok' },
    mixedContent: { status: 'ok' },
  };
  const s = scoreReport(report);
  assert.equal(s.total, 4); // headers1 + cookie1 + tls1 + mixed1（cookie 3個でも 1）
  assert.equal(s.ok, 3);
});

test('スコア：ok 比率からスコア化', () => {
  const report = {
    headers: [{ status: 'ok' }, { status: 'warn' }],
    cookies: { status: 'ok', items: [] },
    tls: { status: 'ok' },
    mixedContent: { status: 'ok' },
  };
  const s = scoreReport(report);
  assert.equal(s.total, 5);
  assert.equal(s.ok, 4);
  assert.equal(s.score, 80);
  assert.equal(s.grade, 'B');
});
