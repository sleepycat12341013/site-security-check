// 純粋な診断ロジック（ネットワーク I/O なし・テスト可能）。
// server.mjs が生データ（ヘッダ / Cookie / 証明書 / HTML）を集めて、ここに渡す。

// ---- 入力 URL の正規化（スキーム省略を許容）----
// "github.com" のようにスキーム無しで来たら https:// を補う。
// すでに "scheme://" が付いていればそのまま（http/https の最終判定は server 側）。
export function normalizeUrl(input) {
  const s = String(input ?? '').trim();
  if (!s) return s;
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`;
}

// ---- CSP の実効性ヒューリスティック ----
// 完全な CSP 監査ではない。「存在するだけ」を ok にして XSS を止められない設定を
// 見逃す誤✅を防ぐのが目的。script/default-src の unsafe-inline / unsafe-eval /
// ワイルドカード(*) という、XSS を素通しにする代表的な弱点だけを検出する。
// （style-src の unsafe-inline はリスクが低く一般的なので警告しない＝過剰⚠️を避ける）
export function cspLooksEffective(v) {
  const s = String(v).toLowerCase();
  if (/'unsafe-eval'/.test(s)) return false;
  const scriptDir = /(?:^|;)\s*(?:script-src|default-src)\b([^;]*)/i.exec(s)?.[1] ?? '';
  if (/'unsafe-inline'/.test(scriptDir)) return false;
  // script/default-src のソースに裸の * がある（= どこからでも読める）
  if (/(?:[\s'"]|^)\*(?:[\s'";]|$)/.test(scriptDir)) return false;
  return true;
}

// ---- セキュリティヘッダ ----
const HEADER_CHECKS = [
  {
    key: 'content-security-policy',
    label: 'Content-Security-Policy',
    ok: (v) => cspLooksEffective(v),
    badWhy: 'CSP はあるが script/default-src に unsafe-inline / unsafe-eval / ワイルドカード(*) があり、XSS を止める層としての実効性が低い。',
    why: 'XSS やデータ注入の被害を抑える最後の砦。未設定だと埋め込み攻撃を止める層が無い。',
  },
  {
    key: 'strict-transport-security',
    label: 'Strict-Transport-Security (HSTS)',
    ok: (v) => { const m = /max-age=(\d+)/i.exec(v); return !!m && Number(m[1]) > 0; },
    badWhy: 'max-age が無い、または max-age=0（HSTS を無効化する値）。ブラウザに常時 HTTPS を強制できていない。',
    why: 'ブラウザに常時 HTTPS を強制する。未設定だと初回や中間者攻撃で HTTP に落とされうる。',
  },
  {
    key: 'x-content-type-options',
    label: 'X-Content-Type-Options',
    ok: (v) => /nosniff/i.test(v),
    badWhy: '値が nosniff ではない。MIME スニッフィングを止められていない。',
    why: 'MIME スニッフィングを止める。nosniff が無いと別タイプとして実行される危険。',
  },
  {
    key: 'x-frame-options',
    label: 'X-Frame-Options',
    ok: (v) => /^(deny|sameorigin)$/i.test(v.trim()),
    badWhy: '値が DENY / SAMEORIGIN ではない。クリックジャッキングを防げていない。',
    why: 'クリックジャッキング対策。未設定だと他サイトに iframe で重ねられる。',
  },
  {
    key: 'referrer-policy',
    label: 'Referrer-Policy',
    ok: (v) => !/unsafe-url/i.test(v),
    badWhy: 'Referrer-Policy が unsafe-url＝常にフル URL を送る設定。リファラ経由の情報漏れを防げていない。',
    why: 'リファラ経由の URL 情報漏れを抑える。未設定だと遷移先に余計な情報が漏れる。',
  },
];

export function checkSecurityHeaders(headers) {
  // headers: 小文字キーの平オブジェクト
  return HEADER_CHECKS.map((h) => {
    const raw = headers[h.key];
    const present = raw != null && String(raw).trim() !== '';
    // detail は日本語の判定（一般ユーザー向け）。生のヘッダ値は value に分けて小さく見せる。
    if (!present) return { label: h.label, status: 'warn', detail: '未設定', why: h.why };
    if (h.ok && !h.ok(String(raw))) {
      return { label: h.label, status: 'warn', detail: '設定あり（推奨されない値）', value: String(raw), why: h.badWhy || h.why };
    }
    return { label: h.label, status: 'ok', detail: '設定あり', value: String(raw), why: '' };
  });
}

// ---- Cookie 属性 ----
export function checkCookies(setCookies) {
  // setCookies: 文字列配列（Set-Cookie 各行）
  if (!setCookies || setCookies.length === 0) {
    return { status: 'ok', items: [], note: 'Set-Cookie なし（Cookie を発行していない）' };
  }
  const items = setCookies.map((line) => {
    // 属性は ';' 区切り。先頭(name=value)を除いた各属性だけを見る。
    // 行全体の部分一致だと値に "secure" 等が含まれるだけで誤検出するため（誤✅）。
    const segments = line.split(';').map((p) => p.trim());
    const name = segments[0].split('=')[0].trim();
    const attrs = segments.slice(1).map((a) => a.toLowerCase());
    const httpOnly = attrs.includes('httponly');
    const secure = attrs.includes('secure');
    const sameSiteVal = attrs.find((a) => a.startsWith('samesite='))?.split('=')[1] ?? '';
    const sameSite = /^(lax|strict|none)$/.test(sameSiteVal) ? sameSiteVal : null;
    const missing = [];
    if (!httpOnly) missing.push('HttpOnly');
    if (!secure) missing.push('Secure');
    // SameSite: 未設定はもちろん、None は「別サイトにも送る＝CSRF 無防備」なので不十分扱い。
    // 値が在るか だけでなく 値が安全か まで見る（None を ✅ にしない）。
    if (!sameSite || sameSite === 'none') missing.push(sameSite === 'none' ? 'SameSite(None=無防備)' : 'SameSite');
    return { name, httpOnly, secure, sameSite, missing, status: missing.length ? 'warn' : 'ok' };
  });
  return { status: items.some((i) => i.status === 'warn') ? 'warn' : 'ok', items };
}

// ---- TLS 証明書 ----
export function checkTLS({ protocol, authorized, authorizationError, daysToExpiry, validTo }) {
  if (protocol !== 'https:') {
    return { status: 'warn', detail: 'HTTPS ではない', why: '通信が暗号化されず盗聴・改ざんが可能。' };
  }
  if (authorized === false) {
    return {
      status: 'warn',
      detail: `証明書が無効: ${authorizationError || '検証失敗'}`,
      why: '証明書チェーンが信頼できない＝なりすましの恐れ。',
    };
  }
  if (typeof daysToExpiry === 'number' && !Number.isNaN(daysToExpiry)) {
    if (daysToExpiry < 0) {
      return { status: 'warn', detail: `期限切れ（${validTo}）`, why: 'ブラウザが警告を出し、信頼が崩れる。即更新を。' };
    }
    if (daysToExpiry <= 14) {
      return {
        status: 'warn',
        detail: `まもなく期限切れ（残り ${daysToExpiry} 日・${validTo}）`,
        why: '失効すると全アクセスがエラーになる。早めに更新を。',
      };
    }
    return { status: 'ok', detail: `有効（残り ${daysToExpiry} 日）`, why: '' };
  }
  // 期限を読めなかった場合：authorized===true（システム検証が通った＝期限切れも除外済）の
  // 時だけ ok。検証が確定していない時は「迷ったら注意側」で warn（曖昧を ✅ にしない）。
  if (authorized === true) {
    return { status: 'ok', detail: '有効（有効期限は取得できず）', why: '' };
  }
  return {
    status: 'warn',
    detail: '証明書を確認できませんでした',
    why: '証明書の検証が完了していない。安全と断定できない。',
  };
}

// ---- 混在コンテンツ（mixed content）----
export function checkMixedContent(html, isHttps) {
  if (!isHttps) return { status: 'ok', detail: 'HTTPS でないため対象外', items: [] };
  if (!html) return { status: 'ok', detail: 'HTML を取得できず（判定スキップ）', items: [] };
  const found = new Set();
  // 実際に読み込まれるサブリソースだけを混在として拾う：
  //   - src= 全般（img / script / iframe / audio / video / source 等）
  //   - <link ... href=>（CSS 等）
  // <a href> はクリックで遷移するだけ＝読み込まないので対象外（誤検出を防ぐ）。
  const patterns = [
    /\ssrc\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi,
    /<link\b[^>]*?\shref\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi,
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(html)) && found.size < 20) found.add(m[1]);
  }
  const items = [...found];
  return items.length
    ? {
        status: 'warn',
        detail: `http:// のリソース ${items.length} 件`,
        items,
        why: 'HTTPS ページ内の HTTP 読み込みは盗聴・改ざんの穴。ブラウザもブロック / 警告する。',
      }
    : { status: 'ok', detail: '混在なし', items: [] };
}

// ---- スコア ----
export function scoreReport(report) {
  // Cookie は何個あっても「まとめて1項目」として採点する。
  // 個別に展開すると Cookie を多く出すサイトほど点数が Cookie に偏ってしまうため。
  // report.cookies.status は「1個でも不備があれば warn」の集約値（checkCookies が算出済）。
  const checks = [
    ...report.headers,
    { status: report.cookies.status },
    report.tls,
    report.mixedContent,
  ];
  const total = checks.length;
  const ok = checks.filter((c) => c.status === 'ok').length;
  const score = total ? Math.round((ok / total) * 100) : 100;
  let grade = 'A';
  if (score < 50) grade = 'D';
  else if (score < 70) grade = 'C';
  else if (score < 90) grade = 'B';
  return { score, grade, ok, total };
}

// ---- 証明書エラーで取得できなかったときの最小レポート ----
// fetch は失敗したが「証明書が無効」が主因のとき用。ヘッダ等は取得できていないので
// 「未設定」と断定せず「未取得」と表示する（取れてないのに無いと言わない＝誤判定回避）。
export function buildCertErrorReport({ url, tls, reason }) {
  const headers = HEADER_CHECKS.map((h) => ({
    label: h.label,
    status: 'warn',
    detail: '未取得',
    why: '証明書エラーのため取得を中止。まず証明書を直してから再診断を。',
  }));
  const report = {
    url,
    finalUrl: url,
    protocol: 'https:',
    headers,
    cookies: { status: 'warn', items: [], note: `未取得（${reason || '証明書エラー'}）` },
    tls: checkTLS({ ...tls, protocol: 'https:' }),
    mixedContent: { status: 'warn', detail: `未取得（${reason || '証明書エラー'}）`, items: [] },
  };
  report.summary = scoreReport(report);
  return report;
}

// ---- 1 サイト分のレポートを組み立てる ----
export function buildReport({ url, finalUrl, protocol, headers, setCookies, tls, html }) {
  const isHttps = protocol === 'https:';
  const report = {
    url,
    finalUrl,
    protocol,
    headers: checkSecurityHeaders(headers),
    cookies: checkCookies(setCookies),
    tls: checkTLS({ ...tls, protocol }),
    mixedContent: checkMixedContent(html, isHttps),
  };
  report.summary = scoreReport(report);
  return report;
}
