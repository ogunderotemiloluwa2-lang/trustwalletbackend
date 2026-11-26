# Trust Wallet API

Authentication API for the Trust Wallet Web front end. Express 5 + Mongoose,
deployed on Render.

The API stores a display name, a bcrypt password hash, an optional bcrypt hash
of the six-digit sign-in code, and the wallet metadata (addresses and labels)
created during onboarding. There is no email address: an account is identified
by the credential the owner signs in with. Wallet keys are derived and encrypted
in the browser and never reach this service.

## Endpoints

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/health` | – | Liveness probe, returns `{"status":"ok"}` |
| `POST` | `/api/auth/register` | – | Create an account, returns a profile + JWT |
| `POST` | `/api/auth/login` | – | Exchange the password **or** the six-digit code for a profile + JWT |
| `POST` | `/api/auth/pin` | Bearer | Store the six-digit sign-in code for the session account |
| `GET` | `/api/auth/me` | Bearer | Return the profile for the session token |
| `POST` | `/api/auth/balance` | `Bearer` | Store the headline balance on the account |
| `POST` | `/api/wallets` | Bearer | Upsert the wallet record for the session account |
| `GET` | `/api/wallets` | Bearer | List the wallets owned by the session account |

Session tokens are HMAC-SHA256 JWTs valid for one hour.

`POST /api/auth/login` accepts `{ "pin" }` or `{ "password" }`. The six-digit code
is the normal sign-in; the wallet password is the fallback when the code is
forgotten. Because there is no email address, the account is located with a
keyed digest of the submitted credential (`passwordLookup` / `pinLookup`) and
then verified against the bcrypt hash, so a database dump alone cannot be used
to enumerate accounts.

The profile returned by every auth route includes `hasPin`, which tells the front
end whether the account already has a six-digit code, and `balance`, the headline
USD amount owned by the account. The balance lives on the user document, so it is
identical on every device and is never reset by signing out or by removing a
wallet from a device. It stays at `0` until an amount is set.

## Local development

```bash
npm install
npm run setup:db     # prompts for the MongoDB URI, generates JWT_SECRET, writes .env
npm run dev          # http://localhost:5000
```

`npm run setup:db` is a one-time step; it creates `.env` from `.env.example` and
fills in a random `JWT_SECRET`.

## Environment variables

| Key | Required | Description |
| --- | --- | --- |
| `MONGODB_URI` | yes | MongoDB Atlas or local connection string |
| `JWT_SECRET` | yes | Random string of at least 32 characters |
| `CORS_ORIGIN` | yes in production | Comma-separated list of allowed browser origins |
| `API_PORT` | no | Local port, defaults to `5000`. Render injects `PORT` instead |

`CORS_ORIGIN` accepts a comma-separated list, so preview deployments can be
allowed alongside production:

```text
CORS_ORIGIN=https://your-app.vercel.app,https://your-app-git-main.vercel.app
```

When `CORS_ORIGIN` is unset the API falls back to `http://localhost:3000`.

## Tests

```bash
npm test        # unit tests (node:test, in-memory model)
npm run test:db # integration tests against the real MongoDB
```

`npm run test:db` skips itself when `MONGODB_URI` is unset, so it never breaks a
normal test run.

## Deploying to Render

1. Create a **Web Service** from this repository.
2. Build command `npm ci`, start command `npm start`.
3. Health check path `/health`.
4. Add `MONGODB_URI`, `JWT_SECRET`, and `CORS_ORIGIN` as environment variables.

[`render.yaml`](./render.yaml) describes the same service as a blueprint, so the
repository can also be deployed with **New → Blueprint**.

## Security notes

- `.env` is git-ignored. Never commit `MONGODB_URI` or `JWT_SECRET`.
- Passwords are hashed with bcrypt; the hash is never returned by the API.
- Mongoose filter sanitization is enabled to block operator injection.
