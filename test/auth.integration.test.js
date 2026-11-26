/**
 * Integration test against a real MongoDB deployment.
 *
 * Unlike server/auth.test.js (which uses an in-memory fake model), this suite
 * connects to the database in MONGODB_URI and exercises the real Mongoose
 * schema, the real unique index, and real bcrypt hashing.
 *
 * Run with:  npm run test:db
 *
 * The suite skips itself when MONGODB_URI is not configured, so it never fails
 * a normal `npm test` run. It only ever creates and deletes the single user it
 * registers, so existing data is left untouched.
 */

require('dotenv').config();

const assert = require('node:assert/strict');
const { after, before, describe, it } = require('node:test');

const mongoose = require('mongoose');
const User = require('../src/models/User');
const { credentialLookup } = require('../src/auth');

const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'integration-test-secret-that-is-long-enough';
const TEST_PASSWORD = `integration-test-password-${Date.now()}`;

const describeWithDatabase = MONGODB_URI ? describe : describe.skip;

describeWithDatabase('MongoDB integration', () => {
  let server;
  let baseUrl;

  before(async () => {
    await mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 15000 });

    // Wait for index builds so the credential lookup indexes are actually in
    // place before the sign-in tests run against a fresh database.
    await User.init();

    // Build the real Express app (including its duplicate-key error handling)
    // around the real model, on an ephemeral port.
    const { createApp } = require('../src/app');
    const app = createApp({ jwtSecret: JWT_SECRET, UserModel: User });
    await new Promise((resolve) => {
      server = app.listen(0, resolve);
    });
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    // Remove only the user this suite created.
    await User.deleteMany({ passwordLookup: credentialLookup(JWT_SECRET, 'password', TEST_PASSWORD) });
    if (server) await new Promise((resolve) => server.close(resolve));
    await mongoose.disconnect();
  });

  const call = async (method, route, body, token) => {
    const response = await fetch(baseUrl + route, {
      method,
      headers: {
        'content-type': 'application/json',
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: response.status, body: await response.json() };
  };

  it('connects to the configured database', async () => {
    const { host, name } = mongoose.connection;
    assert.ok(host, 'expected a connected host');
    assert.ok(name, 'expected a database name in the connection string');
    console.log(`      connected to ${host} / ${name}`);
  });

  it('registers a user and stores a bcrypt hash, not the password', async () => {
    const response = await call('POST', '/api/auth/register', {
      name: 'Integration Test',
      password: TEST_PASSWORD,
    });

    assert.equal(response.status, 201, JSON.stringify(response.body));
    assert.equal(response.body.user.name, 'Integration Test');
    assert.ok(!('passwordHash' in response.body.user), 'response must not expose the hash');
    assert.ok(!('email' in response.body.user), 'the profile must not carry an email address');

    // Read the raw document back out of MongoDB.
    const stored = await User.findOne({
      passwordLookup: credentialLookup(JWT_SECRET, 'password', TEST_PASSWORD),
    }).select('+passwordHash').lean();
    assert.ok(stored, 'expected the user to be persisted');
    assert.match(stored.passwordHash, /^\$2[aby]\$12\$/, 'expected a bcrypt hash at cost 12');
    assert.ok(!stored.passwordHash.includes(TEST_PASSWORD), 'hash must not contain the plaintext');
    assert.ok(stored.createdAt instanceof Date, 'timestamps should be enabled');
  });

  it('signs in with the six-digit code and falls back to the wallet password', async () => {
    const login = await call('POST', '/api/auth/login', { password: TEST_PASSWORD });
    assert.equal(login.status, 200, JSON.stringify(login.body));
    assert.equal(typeof login.body.token, 'string');

    const me = await call('GET', '/api/auth/me', null, login.body.token);
    assert.equal(me.status, 200, JSON.stringify(me.body));
    assert.equal(me.body.user.name, 'Integration Test');
    assert.ok(!('passwordHash' in me.body.user));

    const pin = await call('POST', '/api/auth/pin', { pin: '246810' }, login.body.token);
    assert.equal(pin.status, 200, JSON.stringify(pin.body));
    assert.equal(pin.body.user.hasPin, true);

    const pinLogin = await call('POST', '/api/auth/login', { pin: '246810' });
    assert.equal(pinLogin.status, 200, JSON.stringify(pinLogin.body));
    assert.equal(pinLogin.body.user.hasPin, true);
  });

  it('rejects a wrong password and a wrong code', async () => {
    const wrongPassword = await call('POST', '/api/auth/login', { password: 'not-the-password' });
    assert.equal(wrongPassword.status, 401, JSON.stringify(wrongPassword.body));

    const wrongPin = await call('POST', '/api/auth/login', { pin: '000000' });
    assert.equal(wrongPin.status, 401, JSON.stringify(wrongPin.body));
  });
});
