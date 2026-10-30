import express from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SignJWT, calculateJwkThumbprint, exportJWK, importPKCS8, importSPKI } from 'jose';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const BASE_URL = (process.env.IDV_BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const CLIENT_ID = process.env.IDV_CLIENT_ID || 'demo-okta-client';
const CLIENT_SECRET = process.env.IDV_CLIENT_SECRET || 'change-me-demo-secret';
const BRAND = process.env.IDV_BRAND_NAME || 'Acme Verify';
const KEY_FILE = path.join(__dirname, '.keys.json');

// Accepts a PEM pasted as one line with literal \n, with real newlines, or wrapped in quotes,
// and rebuilds it with proper 64-char base64 lines.
function normalizePem(raw) {
  const s = raw.trim().replace(/^["']|["']$/g, '').replace(/\\n/g, '\n');
  const m = s.match(/-----BEGIN ([A-Z ]+)-----([\s\S]+?)-----END \1-----/);
  // No BEGIN/END lines (they get dropped when copying): assume bare PKCS#8 base64.
  const label = m ? m[1] : 'PRIVATE KEY';
  const body = (m ? m[2] : s).replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/=]+$/.test(body)) return s;
  return `-----BEGIN ${label}-----\n${body.match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`;
}

// ---------- signing key (persisted so restarts don't invalidate Okta's JWKS cache) ----------
async function loadKeys() {
  // Hosted deployments have ephemeral disks, so allow the key to come from an env var.
  if (process.env.IDV_PRIVATE_KEY_PEM) {
    const privatePem = normalizePem(process.env.IDV_PRIVATE_KEY_PEM);
    let publicPem;
    try {
      publicPem = crypto.createPublicKey(crypto.createPrivateKey(privatePem)).export({ type: 'spki', format: 'pem' });
    } catch (e) {
      throw new Error(
        `IDV_PRIVATE_KEY_PEM could not be parsed (${e.code || e.message}). ` +
          'Expected a PKCS#8 key starting with -----BEGIN PRIVATE KEY-----. ' +
          `Received ${process.env.IDV_PRIVATE_KEY_PEM.length} chars, starting "${process.env.IDV_PRIVATE_KEY_PEM.slice(0, 27)}".`,
      );
    }
    const publicKey = await importSPKI(publicPem, 'RS256');
    const kid = await calculateJwkThumbprint(await exportJWK(publicKey));
    return { privateKey: await importPKCS8(privatePem, 'RS256'), publicKey, kid };
  }
  if (fs.existsSync(KEY_FILE)) {
    const { privatePem, publicPem, kid } = JSON.parse(fs.readFileSync(KEY_FILE, 'utf8'));
    return { privateKey: await importPKCS8(privatePem, 'RS256'), publicKey: await importSPKI(publicPem, 'RS256'), kid };
  }
  const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const kid = crypto.randomUUID();
  const privatePem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = pair.publicKey.export({ type: 'spki', format: 'pem' });
  fs.writeFileSync(KEY_FILE, JSON.stringify({ kid, privatePem, publicPem }), { mode: 0o600 });
  return { privateKey: await importPKCS8(privatePem, 'RS256'), publicKey: await importSPKI(publicPem, 'RS256'), kid };
}
const { privateKey, publicKey, kid } = await loadKeys();
const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };

// ---------- in-memory stores (demo only) ----------
const parRequests = new Map(); // request_uri -> PAR params
const authCodes = new Map(); // code -> { par, result }
const events = []; // shown on /admin so the presenter can narrate what happened

const log = (type, detail) => {
  events.unshift({ at: new Date().toISOString(), type, detail });
  events.length = Math.min(events.length, 50);
  console.log(`[${type}]`, typeof detail === 'string' ? detail : JSON.stringify(detail));
};
const b64 = (n = 24) => crypto.randomBytes(n).toString('base64url');
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

// ---------- helpers ----------
function clientAuth(req) {
  let id = req.body.client_id;
  let secret = req.body.client_secret;
  const basic = req.headers.authorization?.match(/^Basic (.+)$/i);
  if (basic) [id, secret] = Buffer.from(basic[1], 'base64').toString().split(':').map(decodeURIComponent);
  const ok =
    id === CLIENT_ID &&
    secret &&
    secret.length === CLIENT_SECRET.length &&
    crypto.timingSafeEqual(Buffer.from(secret), Buffer.from(CLIENT_SECRET));
  return ok ? id : null;
}
const norm = (s) => String(s ?? '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z]/g, '');
function lev(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[a.length][b.length];
}
// Okta always sends fuzzy:true, so tolerate small typos (e.g. Patrick vs Patric)
const fuzzyMatch = (expected, actual) => lev(norm(expected), norm(actual)) <= 2;

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// ---------- discovery + JWKS ----------
app.get('/.well-known/openid-configuration', (_req, res) =>
  res.json({
    issuer: BASE_URL,
    pushed_authorization_request_endpoint: `${BASE_URL}/oauth2/par`,
    authorization_endpoint: `${BASE_URL}/oauth2/idv-authorize`,
    token_endpoint: `${BASE_URL}/token`,
    jwks_uri: `${BASE_URL}/jwks`,
    response_types_supported: ['code'],
    id_token_signing_alg_values_supported: ['RS256'],
    code_challenge_methods_supported: ['S256'],
  }),
);
app.get('/jwks', (_req, res) => res.json({ keys: [publicJwk] }));

// ---------- 1. PAR ----------
app.post('/oauth2/par', (req, res) => {
  res.set({ 'Cache-Control': 'no-cache, no-store', Pragma: 'no-cache' });
  if (!clientAuth(req)) {
    log('par.denied', 'bad client credentials');
    return res.status(401).json({ error: 'invalid_client', error_description: 'Client authentication failed' });
  }
  const p = req.body;
  const bad = (d) => res.status(400).json({ error: 'invalid_request', error_description: d });
  if (p.response_type !== 'code') return bad('response_type must be code');
  if (!p.code_challenge || p.code_challenge_method !== 'S256') return bad('PKCE S256 required');
  if (!p.nonce || !p.state || !p.redirect_uri) return bad('nonce, state and redirect_uri are required');
  let claims = {};
  try {
    claims = p.claims ? JSON.parse(p.claims) : {};
  } catch {
    return bad('claims is not valid JSON');
  }
  const request_uri = `urn:ietf:params:oauth:request_uri:${b64()}`;
  parRequests.set(request_uri, { ...p, claims, createdAt: Date.now() });
  setTimeout(() => parRequests.delete(request_uri), 10 * 60 * 1000).unref(); // UX must allow 10 min
  log('par.accepted', { login_hint: p.login_hint, scope: p.scope, claims });
  res.status(201).json({ request_uri, expires_in: 60 });
});

// ---------- 2. Authorization (the user-facing verification UX) ----------
const requestedClaims = (par) => par.claims?.id_token?.verified_claims?.[0]?.claims || {};
const claimVal = (c) => (c && typeof c === 'object' && 'value' in c ? c.value : '');

app.get('/oauth2/idv-authorize', (req, res) => {
  const par = parRequests.get(req.query.request_uri);
  if (!par) return res.status(400).send(page('Request expired', '<p>This verification request is invalid or has expired. Please restart from your account.</p>'));
  const c = requestedClaims(par);
  const given = claimVal(c.given_name);
  const family = claimVal(c.family_name);
  const flowHint = /recover|reset/i.test(par.scope || '') ? 'Account recovery' : 'Account setup';
  res.send(
    page(
      'Verify your identity',
      `
<div class="steps" id="steps"><span class="on">1 Consent</span><span>2 ID document</span><span>3 Selfie</span><span>4 Result</span></div>
<form method="POST" action="/oauth2/idv-authorize/complete" id="f">
  <input type="hidden" name="request_uri" value="${esc(req.query.request_uri)}">
  <section data-step="1">
    <h2>${esc(flowHint)}: verify it's you</h2>
    <p>Your organization needs to confirm your identity before continuing. ${esc(BRAND)} will check a government ID and a selfie.</p>
    <p class="muted">Okta asked us to confirm: <b>${esc(given)} ${esc(family)}</b></p>
    <label class="chk"><input type="checkbox" id="agree"> I agree to the <a href="#">Terms of Use</a> and <a href="#">Privacy Policy</a></label>
    <button type="button" class="btn" id="n1" disabled>Continue</button>
  </section>
  <section data-step="2" hidden>
    <h2>Scan your ID</h2>
    <div class="cam"><div class="frame"><div class="scan"></div>ID DOCUMENT</div></div>
    <p class="muted">Demo mode: no camera is used. Edit the name as it appears on the ID to simulate a mismatch.</p>
    <div class="row"><label>First name on ID<input name="id_given" value="${esc(given)}"></label>
    <label>Last name on ID<input name="id_family" value="${esc(family)}"></label></div>
    <button type="button" class="btn" id="n2">Capture document</button>
  </section>
  <section data-step="3" hidden>
    <h2>Take a selfie</h2>
    <div class="cam"><div class="frame round"><div class="scan"></div>SELFIE</div></div>
    <label>Simulated liveness / face match
      <select name="face"><option value="pass">Pass: face matches ID</option><option value="fail">Fail: face does not match</option></select>
    </label>
    <button type="submit" class="btn" id="n3">Submit for verification</button>
  </section>
</form>
<script>
  const s=[...document.querySelectorAll('section')],st=[...document.querySelectorAll('#steps span')];
  const go=i=>{s.forEach((e,j)=>e.hidden=j!==i);st.forEach((e,j)=>e.className=j<=i?'on':'')};
  agree.onchange=()=>n1.disabled=!agree.checked;
  n1.onclick=()=>go(1);n2.onclick=()=>go(2);
  document.getElementById('f').onsubmit=()=>{n3.disabled=true;n3.textContent='Verifying…'};
</script>`,
    ),
  );
});

app.post('/oauth2/idv-authorize/complete', async (req, res) => {
  const par = parRequests.get(req.body.request_uri);
  if (!par) return res.status(400).send(page('Request expired', '<p>This request has expired.</p>'));
  parRequests.delete(req.body.request_uri);
  const c = requestedClaims(par);
  const givenOk = fuzzyMatch(claimVal(c.given_name), req.body.id_given);
  const familyOk = fuzzyMatch(claimVal(c.family_name), req.body.id_family);
  const faceOk = req.body.face !== 'fail';
  const verified = givenOk && familyOk && faceOk;
  const code = b64();
  authCodes.set(code, { par, verified, givenOk, familyOk });
  setTimeout(() => authCodes.delete(code), 5 * 60 * 1000).unref();
  log('verification.completed', { user: par.login_hint, verified, givenOk, familyOk, faceOk });
  const cb = new URL(par.redirect_uri);
  cb.searchParams.set('code', code);
  cb.searchParams.set('state', par.state);
  res.redirect(302, cb.toString());
});

// ---------- 3. Token ----------
app.post('/token', async (req, res) => {
  res.set({ 'Cache-Control': 'no-store', Pragma: 'no-cache' });
  const err = (status, error, d) => res.status(status).json({ error, error_description: d });
  if (!clientAuth(req)) return err(401, 'invalid_client', 'Client authentication failed');
  if (req.body.grant_type !== 'authorization_code') return err(400, 'unsupported_grant_type', 'authorization_code only');
  const entry = authCodes.get(req.body.code);
  authCodes.delete(req.body.code); // single use
  if (!entry) return err(400, 'invalid_grant', 'Unknown, used or expired code');
  const { par, verified, givenOk, familyOk } = entry;
  if (req.body.redirect_uri !== par.redirect_uri) return err(400, 'invalid_grant', 'redirect_uri mismatch');
  const challenge = crypto.createHash('sha256').update(req.body.code_verifier || '').digest('base64url');
  if (challenge !== par.code_challenge) return err(400, 'invalid_grant', 'PKCE verification failed');

  const c = requestedClaims(par);
  // Per Okta: return MATCHED for a verified claim, null for one that did not match
  const out = {};
  for (const [name, spec] of Object.entries(c)) {
    if (name === 'address') {
      out.address = Object.fromEntries(Object.keys(spec).map((k) => [k, { fuzzy: true, value: verified ? 'MATCHED' : null }]));
      continue;
    }
    const ok = name === 'given_name' ? givenOk : name === 'family_name' ? familyOk : verified;
    out[name] = { fuzzy: true, value: ok ? 'MATCHED' : null };
  }
  const now = Math.floor(Date.now() / 1000);
  const idToken = await new SignJWT({
    nonce: par.nonce,
    verified_claims: [
      {
        verification: {
          trust_framework: 'IDV-DELEGATED',
          assurance_level: verified ? 'VERIFIED' : 'FAILED',
          time: new Date().toISOString().slice(0, 19),
          verification_process: `session-${b64(6)}`,
        },
        claims: out,
      },
    ],
  })
    .setProtectedHeader({ alg: 'RS256', kid, typ: 'JWT' })
    .setIssuer(BASE_URL)
    .setAudience(req.body.client_id || CLIENT_ID)
    .setSubject(par.login_hint || 'demo-user')
    .setIssuedAt(now - 5)
    .setExpirationTime(now + 3600)
    .sign(privateKey);
  log('token.issued', { sub: par.login_hint, assurance: verified ? 'VERIFIED' : 'FAILED' });
  res.json({ access_token: b64(), token_type: 'Bearer', expires_in: 3600, id_token: idToken });
});

// ---------- presenter event log ----------
app.get('/admin', (_req, res) =>
  res.send(
    page(
      'Vendor event log',
      `<p class="muted">What ${esc(BRAND)} saw from Okta. Auto-refreshes.</p>
<table><tr><th>Time</th><th>Event</th><th>Detail</th></tr>${events
        .map((e) => `<tr><td>${esc(e.at.slice(11, 19))}</td><td>${esc(e.type)}</td><td><code>${esc(JSON.stringify(e.detail))}</code></td></tr>`)
        .join('')}</table><script>setTimeout(()=>location.reload(),3000)</script>`,
    ),
  ),
);
app.get('/', (_req, res) => res.redirect('/admin'));

function page(title, body) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · ${esc(BRAND)}</title>
<style>
body{margin:0;background:#f3f5f9;font-family:-apple-system,Segoe UI,Inter,sans-serif;color:#14213d}
header{background:#0b3d91;color:#fff;padding:14px 24px;font-weight:700;font-size:18px}
main{max-width:520px;margin:28px auto;background:#fff;border-radius:14px;padding:26px 28px;box-shadow:0 2px 14px rgba(0,0,0,.08)}
h2{margin-top:0}.muted{color:#5b6785;font-size:14px}
.steps{display:flex;gap:6px;margin-bottom:18px;font-size:12px}.steps span{flex:1;padding:6px;border-radius:6px;background:#e6eaf3;text-align:center}.steps .on{background:#0b3d91;color:#fff}
.btn{margin-top:14px;width:100%;padding:12px;border:0;border-radius:10px;background:#0b3d91;color:#fff;font-size:16px;cursor:pointer}.btn:disabled{opacity:.4}
.chk{display:block;margin:14px 0}label{display:block;font-size:13px;color:#5b6785;margin-top:10px}
input:not([type=checkbox]),select{display:block;width:100%;box-sizing:border-box;margin-top:4px;padding:9px;border:1px solid #cfd6e4;border-radius:8px;font-size:15px}
.row{display:flex;gap:10px}.row label{flex:1}
.cam{display:flex;justify-content:center;margin:14px 0}.frame{position:relative;overflow:hidden;width:300px;height:180px;border:2px dashed #0b3d91;border-radius:12px;display:flex;align-items:center;justify-content:center;color:#0b3d91;font-weight:700;background:#eef3ff}
.frame.round{width:190px;height:190px;border-radius:50%}
.scan{position:absolute;left:0;right:0;height:3px;background:#1d4ed8;animation:s 1.8s linear infinite}@keyframes s{from{top:0}to{top:100%}}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:6px;border-bottom:1px solid #e3e8f0;vertical-align:top}code{word-break:break-all}
</style></head><body><header>🛡 ${esc(BRAND)}</header><main>${body}</main></body></html>`;
}

app.listen(PORT, () => {
  console.log(`\n${BRAND} mock IDV vendor listening on :${PORT}`);
  console.log(`  Issuer:        ${BASE_URL}`);
  console.log(`  Event log:     ${BASE_URL}/admin`);
  console.log(`  Discovery:     ${BASE_URL}/.well-known/openid-configuration\n`);
});
