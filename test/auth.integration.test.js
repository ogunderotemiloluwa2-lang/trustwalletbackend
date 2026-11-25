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
 * a normal `npm test` run. It only ever creates and deletes one user whose email
 * is prefixed with `integration-test-`, so existing data is left untouched.
 */

require('dotenv').config();

const assert = require('node:assert/strict');
const { after, before, describe, it } = require('node:test');

const mongoose = require('mongoose');
const User = require('../src/models/User');

const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'integration-test-secret-that-is-long-enough';
const TEST_EMAIL = `integration-test-${Date.now()}@example.com`;
const TEST_PASSWORD = 'integration-test-password';

const describeWithDatabase = MONGODB_URI ? describe : describe.skip;

describeWithDatabase('MongoDB integration', () => {
  let server;
  let baseUrl;

  before(async () => {
    await mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 15000 });

    // Wait for index builds so the unique email constraint is actually in place
    // before the duplicate-registration test runs against a fresh database.
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
    await User.deleteMany({ email: TEST_EMAIL });
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
      email: TEST_EMAIL,
      name: 'Integration Test',
      password: TEST_PASSWORD,
    });

    assert.equal(response.status, 201, JSON.stringify(response.body));
    assert.equal(response.body.user.email, TEST_EMAIL);
    assert.ok(!('passwordHash' in response.body.user), 'response must not expose the hash');

    // Read the raw document back out of MongoDB.
    const stored = await User.findOne({ email: TEST_EMAIL }).select('+passwordHash').lean();
    assert.ok(stored, 'expected the user to be persisted');
    assert.match(stored.passwordHash, /^\$2[aby]\$12\$/, 'expected a bcrypt hash at cost 12');
    assert.ok(!stored.passwordHash.includes(TEST_PASSWORD), 'hash must not contain the plaintext');
    assert.ok(stored.createdAt instanceof Date, 'timestamps should be enabled');
  });

  it('enforces the unique email index', async () => {
    const response = await call('POST', '/api/auth/register', {
      email: TEST_EMAIL,
      password: TEST_PASSWORD,
    });
    assert.equal(response.status, 409, JSON.stringify(response.body));
  });

  it('logs in and returns the profile from a bearer token', async () => {
    const login = await call('POST', '/api/auth/login', { email: TEST_EMAIL, password: TEST_PASSWORD });
    assert.equal(login.status, 200, JSON.stringify(login.body));
    assert.equal(typeof login.body.token, 'string');

    const me = await call('GET', '/api/auth/me', null, login.body.token);
    assert.equal(me.status, 200, JSON.stringify(me.body));
    assert.equal(me.body.user.email, TEST_EMAIL);
    assert.ok(!('passwordHash' in me.body.user));
  });

  it('rejects a wrong password', async () => {
    const response = await call('POST', '/api/auth/login', { email: TEST_EMAIL, password: 'not-the-password' });
    assert.equal(response.status, 401, JSON.stringify(response.body));
  });
});
