// Registers the mock IDV vendor in Okta and wires it into the Account Management Policy.
//   npm run setup:okta      create IdP + rules
//   npm run teardown:okta   remove them again
// Needs OKTA_ORG_URL, OKTA_API_TOKEN, OKTA_TEST_GROUP_ID, IDV_BASE_URL, IDV_CLIENT_ID, IDV_CLIENT_SECRET.
import fs from 'node:fs';

const need = (k) => {
  if (!process.env[k]) throw new Error(`Missing env var ${k}`);
  return process.env[k];
};
const ORG = need('OKTA_ORG_URL').replace(/\/$/, '');
const TOKEN = need('OKTA_API_TOKEN');
const IDV = need('IDV_BASE_URL').replace(/\/$/, '');
const BRAND = process.env.IDV_BRAND_NAME || 'Acme Verify';
const STATE_FILE = new URL('../.okta-state.json', import.meta.url);
const IDP_NAME = `${BRAND} (Custom IDV demo)`;

async function okta(method, path, body) {
  const res = await fetch(`${ORG}${path}`, {
    method,
    headers: { Authorization: `SSWS ${TOKEN}`, 'Content-Type': 'application/json', Accept: 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  const json = text ? JSON.parse(text) : null;
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status}: ${text}`);
  return json;
}
const readState = () => (fs.existsSync(STATE_FILE) ? JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')) : {});

async function findAccountManagementPolicy() {
  // The guide says "retrieve the account management policy ID" without naming the policy type,
  // so look at ACCESS_POLICY and pick the account-management one by name.
  const policies = await okta('GET', '/api/v1/policies?type=ACCESS_POLICY');
  const p = policies.find((x) => /account management/i.test(x.name));
  if (!p) {
    throw new Error(
      `No account management policy found among: ${policies.map((x) => x.name).join(', ')}. ` +
        'Check that Identity Verification / account management is enabled for the org.',
    );
  }
  return p.id;
}

async function setup() {
  const groupId = need('OKTA_TEST_GROUP_ID');
  const idp = await okta('POST', '/api/v1/idps', {
    type: 'IDV_STANDARD',
    name: IDP_NAME,
    protocol: {
      type: 'ID_PROOFING',
      endpoints: {
        par: { url: `${IDV}/oauth2/par`, binding: 'HTTP-REDIRECT' },
        authorization: { url: `${IDV}/oauth2/idv-authorize`, binding: 'HTTP-REDIRECT' },
        token: { url: `${IDV}/token`, binding: 'HTTP-POST' },
        jwks: { url: `${IDV}/jwks`, binding: 'HTTP-REDIRECT' },
      },
      issuer: { url: IDV },
      scopes: ['profile', 'identity_assurance', 'openid'],
      credentials: { client: { client_id: need('IDV_CLIENT_ID'), client_secret: need('IDV_CLIENT_SECRET') } },
    },
    properties: {
      idvMetadata: { vendorDisplayName: BRAND, termsOfUse: `${IDV}/terms`, privacyPolicy: `${IDV}/privacy` },
    },
    policy: {
      provisioning: { action: 'DISABLED' },
      accountLink: { action: 'AUTO' },
      subject: { userNameTemplate: { template: 'source.userName' }, matchType: 'USERNAME' },
      maxClockSkew: 0,
    },
  });
  console.log(`Created IdP ${idp.id}`);

  const policyId = await findAccountManagementPolicy();
  const mkRule = (name, priority, expression) =>
    okta('POST', `/api/v1/policies/${policyId}/rules`, {
      type: 'ACCESS_POLICY',
      name,
      priority,
      conditions: {
        people: { groups: { include: [groupId] } },
        network: { connection: 'ANYWHERE' },
        riskScore: { level: 'ANY' },
        elCondition: { condition: expression },
      },
      actions: { appSignOn: { access: 'ALLOW', verificationMethod: { id: idp.id, type: 'ID_PROOFING' } } },
    });

  const enroll = await mkRule(`${BRAND}: IDV on authenticator enroll`, 1, "accessRequest.operation == 'enroll'");
  const recover = await mkRule(
    `${BRAND}: IDV on password recovery`,
    2,
    "accessRequest.authenticator.key == 'okta_password' && accessRequest.operation == 'recover'",
  );
  fs.writeFileSync(STATE_FILE, JSON.stringify({ idpId: idp.id, policyId, ruleIds: [enroll.id, recover.id] }, null, 2));
  console.log(`Created rules ${enroll.id}, ${recover.id} on policy ${policyId}`);
  console.log(`\nRedirect URI to allow on the vendor side: ${ORG}/idp/identity-verification/callback`);
  console.log('(use your custom domain instead if one is configured)');
}

async function teardown() {
  const s = readState();
  if (!s.idpId) return console.log('Nothing to tear down (.okta-state.json not found).');
  for (const r of s.ruleIds || []) await okta('DELETE', `/api/v1/policies/${s.policyId}/rules/${r}`).catch((e) => console.warn(e.message));
  await okta('POST', `/api/v1/idps/${s.idpId}/lifecycle/deactivate`).catch(() => {});
  await okta('DELETE', `/api/v1/idps/${s.idpId}`).catch((e) => console.warn(e.message));
  fs.rmSync(STATE_FILE, { force: true });
  console.log('Removed IdP and rules.');
}

(process.argv.includes('--teardown') ? teardown() : setup()).catch((e) => {
  console.error(e.message);
  process.exit(1);
});
