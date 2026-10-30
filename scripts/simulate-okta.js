// Plays Okta's role against the mock vendor to verify the contract without an Okta tenant.
//   node --env-file=.env scripts/simulate-okta.js [--mismatch]
import crypto from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const IDV = (process.env.IDV_BASE_URL || 'http://localhost:3000').replace(/\/$/, '');
const CLIENT_ID = process.env.IDV_CLIENT_ID || 'demo-okta-client';
const CLIENT_SECRET = process.env.IDV_CLIENT_SECRET || 'change-me-demo-secret';
const mismatch = process.argv.includes('--mismatch');
const REDIRECT = 'https://example.okta.com/idp/identity-verification/callback';

const verifier = crypto.randomBytes(32).toString('base64url');
const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
const nonce = crypto.randomUUID();
const state = crypto.randomUUID();

const claims = {
  id_token: {
    verified_claims: [
      {
        verification: {
          trust_framework: { value: 'IDV-DELEGATED', essential: true },
          assurance_level: { value: 'VERIFIED', essential: true },
        },
        claims: { given_name: { value: 'Patrick', fuzzy: true }, family_name: { value: 'Jones', fuzzy: true } },
      },
    ],
  },
};

const par = await fetch(`${IDV}/oauth2/par`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    response_type: 'code', client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
    code_challenge: challenge, code_challenge_method: 'S256', scope: 'openid profile identity_assurance',
    nonce, state, login_hint: 'demo-user-1', redirect_uri: REDIRECT, claims: JSON.stringify(claims),
  }),
});
const parBody = await par.json();
console.log('PAR', par.status, parBody);

const page = await fetch(`${IDV}/oauth2/idv-authorize?request_uri=${encodeURIComponent(parBody.request_uri)}`);
console.log('Authorize page', page.status);

const done = await fetch(`${IDV}/oauth2/idv-authorize/complete`, {
  method: 'POST', redirect: 'manual',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    request_uri: parBody.request_uri, id_given: mismatch ? 'Zachariah' : 'Patric', id_family: 'Jones', face: 'pass',
  }),
});
const cb = new URL(done.headers.get('location'));
console.log('Callback', cb.origin + cb.pathname, 'state ok:', cb.searchParams.get('state') === state);

const tok = await fetch(`${IDV}/token`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code', client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
    code: cb.searchParams.get('code'), code_verifier: verifier, redirect_uri: REDIRECT,
  }),
});
const tokBody = await tok.json();
console.log('Token', tok.status);
const { payload } = await jwtVerify(tokBody.id_token, createRemoteJWKSet(new URL(`${IDV}/jwks`)), {
  issuer: IDV, audience: CLIENT_ID,
});
console.log('nonce echoed:', payload.nonce === nonce);
console.log(JSON.stringify(payload.verified_claims, null, 2));
