// 薄い API + 静的フロント。依存ゼロ（Node 標準のみ）・鍵なし・保存なし。
// GET /            … index.html
// GET /style.css   … style.css
// GET /check?url=  … 指定 URL を読むだけで診断し JSON を返す
//
// 安全設計：他人のサイトを「読むだけ」。保存しない。内部/プライベートアドレスは
// SSRF 防止のため診断を拒否する（v1 で公開しても踏み台にされないように最初から入れる）。

import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import net from 'node:net';
import dns from 'node:dns/promises';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { buildReport, normalizeUrl, buildCertErrorReport } from './check.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;

// ---- SSRF 防止：プライベート / ループバック / リンクローカルを弾く ----
function isPrivateIP(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;          // リンクローカル
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
    return false;
  }
  const low = ip.toLowerCase();
  // IPv4 射影アドレス（::ffff:a.b.c.d）は中の IPv4 として再判定（変装を見抜く）。
  // dotted でない綴り（hex 形など）は解釈できない＝安全側で弾く。
  if (low.startsWith('::ffff:')) {
    const v4 = low.slice(7);
    return net.isIPv4(v4) ? isPrivateIP(v4) : true;
  }
  return (
    low === '::' ||   // 未指定（全ゼロ＝自分自身に化けうる）
    low === '::1' ||  // ループバック
    low.startsWith('fc') ||
    low.startsWith('fd') ||
    low.startsWith('fe80')
  );
}

// hostname を1回だけ解決し、内部IPなら弾き、接続先に固定する検証済みIP {address, family} を返す。
// 検査したIPと実際に接続するIPを一致させることで DNS リバインディング(TOCTOU)を封じる。
async function resolvePublicIP(hostname) {
  if (/^localhost$/i.test(hostname)) throw new Error('内部アドレスは診断できません');
  let addrs;
  try {
    addrs = await dns.lookup(hostname, { all: true });
  } catch {
    throw new Error('ホスト名を解決できません');
  }
  for (const { address } of addrs) {
    if (isPrivateIP(address)) throw new Error('内部 / プライベートアドレスは診断できません（SSRF 防止）');
  }
  return addrs[0]; // 以降この検証済みIPに固定して接続する
}

// ---- TLS 証明書の生データを取得（判定は check.mjs）----
// 検証済みIPに固定して接続（servername は元ホスト名＝SNI/証明書整合）。DNSは1回だけ＝リバインド不可。
async function getCert(hostname, port = 443, timeout = 5000) {
  let pinned;
  try {
    pinned = await resolvePublicIP(hostname);
  } catch (e) {
    return { authorized: false, authorizationError: e.message };
  }
  return new Promise((resolve) => {
    // rejectUnauthorized:false ＝ 不正な証明書でも接続して中身を読む（自己署名/期限切れを
    // 「取得失敗」で潰さず「証明書が無効」と診断するため）。読むだけ・データは送らない＝安全。
    const socket = tls.connect({ host: pinned.address, port, servername: hostname, timeout, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      const authorized = socket.authorized;
      const authorizationError = socket.authorizationError ? String(socket.authorizationError) : null;
      socket.end();
      if (!cert || Object.keys(cert).length === 0) return resolve({ authorized, authorizationError });
      const validTo = cert.valid_to;
      const daysToExpiry = Math.floor((new Date(validTo).getTime() - Date.now()) / 86_400_000);
      resolve({ authorized, authorizationError, validTo, validFrom: cert.valid_from, daysToExpiry });
    });
    socket.on('error', (e) => resolve({ authorized: false, authorizationError: e.message }));
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ authorized: false, authorizationError: 'TLS 接続タイムアウト' });
    });
  });
}

const MAX_REDIRECTS = 5;
const UA = 'site-security-check/0.1 (read-only hygiene scan)';

// 1ホップ分のリクエスト。検証済みIP(host)へ接続し、Host/SNI は元ホスト名にする。
// これで「検査したIP＝接続するIP」が保証され、DNS リバインドが効かない。
function requestOnce(pinnedIP, urlObj, timeout) {
  return new Promise((resolve, reject) => {
    const isHttps = urlObj.protocol === 'https:';
    const lib = isHttps ? https : http;
    const req = lib.request(
      {
        host: pinnedIP.address,
        servername: urlObj.hostname, // https のみ使用（SNI）。証明書は元ホスト名で検証される
        port: urlObj.port || (isHttps ? 443 : 80),
        path: (urlObj.pathname || '/') + urlObj.search,
        method: 'GET',
        headers: { Host: urlObj.host, 'User-Agent': UA, Accept: '*/*' },
        timeout,
        // rejectUnauthorized は既定 true：不正証明書は error → 証明書エラー診断へ回す
      },
      (res) => resolve(res),
    );
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('タイムアウト')));
    req.end();
  });
}

// リダイレクトを手動で追い、毎ホップ resolvePublicIP で検査＋IP固定してから繋ぐ。
// redirect 任せだと最初のホストしか検査されず、302 で内部へ飛ばされて SSRF が貫通する。
async function fetchPinned(startHref, timeoutMs) {
  let current = startHref;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const urlObj = new URL(current);
    if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
      const e = new Error('http/https の URL のみ診断できます'); e.code = 'SSRF_BLOCKED'; throw e;
    }
    // 標準ポート(http:80 / https:443)以外は拒否（公開ホストのポートスキャン悪用を防ぐ）
    const stdPort = urlObj.protocol === 'https:' ? '443' : '80';
    if (urlObj.port !== '' && urlObj.port !== stdPort) {
      const e = new Error('標準ポート(80 / 443)以外は診断できません'); e.code = 'SSRF_BLOCKED'; throw e;
    }
    let pinnedIP;
    try {
      pinnedIP = await resolvePublicIP(urlObj.hostname);
    } catch (err) {
      const e = new Error(hop === 0 ? err.message : `リダイレクト先が内部アドレスです（SSRF 防止）: ${urlObj.hostname}`);
      e.code = 'SSRF_BLOCKED';
      throw e;
    }
    const res = await requestOnce(pinnedIP, urlObj, timeoutMs);
    const status = res.statusCode;
    if (status >= 300 && status < 400 && res.headers.location) {
      res.resume(); // 本文を捨ててソケットを解放
      current = new URL(res.headers.location, urlObj.href).href;
      continue;
    }
    return { res, finalUrl: urlObj.href };
  }
  throw new Error('リダイレクトが多すぎます');
}

// 本文を最大 max バイトで打ち切って読む（巨大レスポンスでの OOM/DoS を防ぐ）。
function readTextCapped(res, max) {
  return new Promise((resolve) => {
    const chunks = [];
    let total = 0;
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks).toString('utf8').slice(0, max));
    };
    res.on('data', (c) => {
      if (settled) return;
      chunks.push(c);
      total += c.length;
      if (total >= max) { res.destroy(); finish(); }
    });
    res.on('end', finish);
    res.on('error', finish);
    res.on('close', finish);
  });
}

async function diagnose(target) {
  let u;
  try {
    u = new URL(normalizeUrl(target));
  } catch {
    throw new Error('URL の形式が正しくありません');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('http / https の URL を入力してください');

  // ページ取得（10 秒）。リダイレクトは fetchPinned が毎ホップ検査＋IP固定して追う。
  // 最初のホストの SSRF 検査も fetchPinned の hop0 が担う。
  let res = null;
  let finalUrl = u.href;
  let html = '';
  let fetchError = null;
  try {
    ({ res, finalUrl } = await fetchPinned(u.href, 8_000));
    const ct = res.headers['content-type'] || '';
    if (ct.includes('text/html')) html = await readTextCapped(res, 500_000);
    else res.resume(); // 本文を読まないなら捨てる
  } catch (e) {
    if (e.code === 'SSRF_BLOCKED') throw e; // 内部アドレス＝明確に拒否（取得失敗で誤魔化さない）
    fetchError = e.message || '取得失敗';
  }

  // fetch 失敗時：HTTPS で証明書が無効なら、それを最重要 finding として報告する
  // （「取得に失敗」で終わらせない＝自己署名・期限切れこそ診断で一番見せたい所）。
  if (!res) {
    if (u.protocol === 'https:') {
      const tlsInfo = await getCert(u.hostname);
      if (tlsInfo.authorized === false) {
        return buildCertErrorReport({ url: u.href, tls: tlsInfo, reason: fetchError });
      }
    }
    throw new Error(`取得に失敗: ${fetchError}`);
  }

  // node の res.headers はキー小文字化済みオブジェクト。set-cookie は配列で来る。
  const headers = {};
  for (const [k, v] of Object.entries(res.headers)) {
    if (k === 'set-cookie') continue;
    headers[k] = Array.isArray(v) ? v.join(', ') : v;
  }
  const sc = res.headers['set-cookie'];
  const setCookies = Array.isArray(sc) ? sc : sc ? [sc] : [];

  const finalProtocol = new URL(finalUrl).protocol;
  const tlsInfo = finalProtocol === 'https:' ? await getCert(new URL(finalUrl).hostname) : {};

  return buildReport({ url: u.href, finalUrl, protocol: finalProtocol, headers, setCookies, tls: tlsInfo, html });
}

// ---- HTTP ----
function json(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(body);
}

async function serveFile(res, name, type) {
  try {
    const buf = await readFile(join(__dirname, name));
    res.writeHead(200, { 'content-type': type, 'cache-control': 'no-store' });
    res.end(buf);
  } catch {
    res.writeHead(404);
    res.end('Not Found');
  }
}

// ---- レート制限（踏み台/DoS 増幅の抑制）----
// 依存ゼロの簡易固定ウィンドウ：1 IP あたり RL_WINDOW_MS 間に RL_MAX 回まで。
const RL_WINDOW_MS = 60_000;
const RL_MAX = 20;
const rlMap = new Map(); // ip -> { count, resetAt }
function rateLimited(ip) {
  const now = Date.now();
  let e = rlMap.get(ip);
  if (!e || now >= e.resetAt) { e = { count: 0, resetAt: now + RL_WINDOW_MS }; rlMap.set(ip, e); }
  e.count++;
  if (rlMap.size > 10_000) for (const [k, v] of rlMap) if (now >= v.resetAt) rlMap.delete(k); // 簡易掃除
  return e.count > RL_MAX;
}
// 外向きリクエストの同時実行上限（プロキシ/スキャナ化の抑制）
const MAX_INFLIGHT = 8;
let inflight = 0;

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (req.method === 'GET' && url.pathname === '/') return serveFile(res, 'index.html', 'text/html; charset=utf-8');
  if (req.method === 'GET' && url.pathname === '/style.css') return serveFile(res, 'style.css', 'text/css; charset=utf-8');

  if (req.method === 'GET' && url.pathname === '/check') {
    const ip = req.socket.remoteAddress || 'unknown';
    if (rateLimited(ip)) return json(res, 429, { error: 'リクエストが多すぎます。少し待って再試行してください。' });
    if (inflight >= MAX_INFLIGHT) return json(res, 503, { error: '混雑しています。少し待って再試行してください。' });
    const target = url.searchParams.get('url');
    if (!target) return json(res, 400, { error: 'url パラメータが必要です' });
    inflight++;
    try {
      return json(res, 200, await diagnose(target));
    } catch (e) {
      return json(res, 200, { error: e.message });
    } finally {
      inflight--;
    }
  }

  res.writeHead(404);
  res.end('Not Found');
});

server.listen(PORT, () => {
  console.log(`site-security-check 起動: http://localhost:${PORT}`);
});
