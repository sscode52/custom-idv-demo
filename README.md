# Custom IDV demo for Okta

A mock ID verification vendor ("Acme Verify", rebrandable) that implements the Okta Custom IDV contract:
PAR -> authorize -> token -> signed `id_token` with `verified_claims` (`IDV-DELEGATED` / `VERIFIED`|`FAILED`).
Okta calls it during **authenticator enrollment** and **password recovery**.

## Run it

```bash
cp config.sample.env .env      # fill in values
npm install
npm start                      # vendor on :3000
ngrok http 3000                # or cloudflared; put the https URL in IDV_BASE_URL, restart
```

Presenter view of what the vendor received from Okta: `$IDV_BASE_URL/admin`.

## Wire it into Okta

1. Admin Console: create an API token and a test group containing your demo user; put both in `.env`.
2. `npm run setup:okta` creates the `IDV_STANDARD` IdP and two rules on the account management policy:
   - `accessRequest.operation == 'enroll'`
   - `accessRequest.authenticator.key == 'okta_password' && accessRequest.operation == 'recover'`
3. The user's Okta first/last name must match what is typed on the "ID" screen (small typos pass: matching is fuzzy).
4. `npm run teardown:okta` removes everything.

If you use an Okta custom domain, set `OKTA_ORG_URL` to it; the callback is `<domain>/idp/identity-verification/callback`.

## Demo script

| Scenario | How |
|---|---|
| Onboarding (new user enrolls Okta Verify/passkey) | Sign in as a test-group user and start authenticator enrollment: Okta redirects to the vendor |
| Password reset | "Forgot password" as a test-group user: redirect to vendor before reset is allowed |
| Pass | Keep names as prefilled, face = Pass |
| Fail | Change the name on the ID screen, or set face = Fail: Okta denies |

Check Okta System Log for `user.identity_verification.start` and `user.identity_verification`.

## Offline check (no Okta needed)

`node scripts/simulate-okta.js` / `--mismatch` plays Okta's side and verifies the ID token against `/jwks`.

## Notes

- State is in memory; restart clears pending requests. The signing key persists in `.keys.json`.
- To demo a real vendor (Persona, Incode, etc.), skip this app: register their endpoints with the same IdP payload.
