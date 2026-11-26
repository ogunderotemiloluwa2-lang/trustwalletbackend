const assert = require('node:assert/strict');
const { after, before, test } = require('node:test');
const bcrypt = require('bcryptjs');
const express = require('express');
const { createAuthRouter } = require('../src/auth');
const mongoose = require('mongoose');
const UserSchemaModel = require('../src/models/User');

const users = new Map();
// Mimics a Mongoose query: thenable and chainable with `.select()`.
const query = (user) => ({
  select: () => Promise.resolve(user),
  then: (resolve, reject) => Promise.resolve(user).then(resolve, reject),
});
const User = {
  async create(record) {
    const user = { _id: String(users.size + 1), ...record };
    user.save = async () => user;
    users.set(user._id, user);
    return user;
  },
  findOne(filter) {
    const match = [...users.values()].find((user) =>
      (filter.passwordLookup !== undefined && user.passwordLookup === filter.passwordLookup) ||
      (filter.pinLookup !== undefined && user.pinLookup === filter.pinLookup)
    ) || null;
    return {
      select: async () => match,
    };
  },
  findById(id) {
    return query(users.get(id) || null);
  },
};

const app = express();
app.use(express.json());
app.use('/api/auth', createAuthRouter({ User, jwtSecret: 'test-secret-with-more-than-thirty-two-characters' }));
let server;
let baseUrl;

before(async () => {
  server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}/api/auth`;
});

after(async () => {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

test('enables Mongoose filter sanitization and validates user schema fields', async () => {
  assert.equal(mongoose.get('sanitizeFilter'), true);
  assert.equal(UserSchemaModel.schema.path('passwordHash').options.select, false);
  assert.equal(UserSchemaModel.schema.path('passwordLookup').options.select, false);
  assert.equal(UserSchemaModel.schema.path('pinHash').options.select, false);
  assert.equal(UserSchemaModel.schema.path('email'), undefined);
  await assert.rejects(
    new UserSchemaModel({ passwordHash: 'hash' }).validate(),
    { name: 'ValidationError' }
  );
});

test('registers a user with a password hash and returns a profile without the hash', async () => {
  const response = await fetch(`${baseUrl}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'a secure password', name: 'Person' }),
  });
  const data = await response.json();
  const savedUser = users.get('1');

  assert.equal(response.status, 201);
  assert.equal(data.user.name, 'Person');
  assert.equal(Object.hasOwn(data.user, 'email'), false);
  assert.equal(Object.hasOwn(data.user, 'passwordHash'), false);
  assert.notEqual(savedUser.passwordHash, 'a secure password');
  assert.equal(await bcrypt.compare('a secure password', savedUser.passwordHash), true);
  assert.equal(typeof savedUser.passwordLookup, 'string');
  assert.equal(typeof data.token, 'string');
});

test('rejects invalid registration input and invalid login credentials', async () => {
  const invalidRegistration = await fetch(`${baseUrl}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'short' }),
  });
  const invalidLogin = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'incorrect password' }),
  });

  assert.equal(invalidRegistration.status, 400);
  assert.equal(invalidLogin.status, 401);
});

test('authenticates login and returns the profile from the bearer token', async () => {
  const login = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'a secure password' }),
  });
  const session = await login.json();
  const profileResponse = await fetch(`${baseUrl}/me`, {
    headers: { Authorization: `Bearer ${session.token}` },
  });
  const profile = await profileResponse.json();
  const unauthenticated = await fetch(`${baseUrl}/me`);

  assert.equal(login.status, 200);
  assert.equal(profileResponse.status, 200);
  assert.deepEqual(profile.user, {
    id: '1',
    name: 'Person',
    hasPin: false,
    balance: 0,
  });
  assert.equal(unauthenticated.status, 401);
});

test('stores the headline balance on the account so it survives signing out', async () => {
  const login = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'a secure password' }),
  });
  const session = await login.json();

  const invalid = await fetch(`${baseUrl}/balance`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.token}` },
    body: JSON.stringify({ balance: -1 }),
  });
  assert.equal(invalid.status, 400);

  const saved = await fetch(`${baseUrl}/balance`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.token}` },
    body: JSON.stringify({ balance: 250 }),
  });
  const body = await saved.json();
  assert.equal(saved.status, 200);
  assert.equal(body.user.balance, 250);

  // A fresh sign-in must read the stored amount back rather than resetting it.
  const secondLogin = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'a secure password' }),
  });
  const secondSession = await secondLogin.json();
  assert.equal(secondSession.user.balance, 250);

  const profileResponse = await fetch(`${baseUrl}/me`, {
    headers: { Authorization: `Bearer ${secondSession.token}` },
  });
  const profile = await profileResponse.json();
  assert.equal(profile.user.balance, 250);

  const unauthenticated = await fetch(`${baseUrl}/balance`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ balance: 250 }),
  });
  assert.equal(unauthenticated.status, 401);
});

test('stores a six-digit code and signs in with it instead of the password', async () => {
  const login = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'a secure password' }),
  });
  const session = await login.json();

  const rejected = await fetch(`${baseUrl}/pin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.token}` },
    body: JSON.stringify({ pin: '12345' }),
  });
  assert.equal(rejected.status, 400);

  const saved = await fetch(`${baseUrl}/pin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.token}` },
    body: JSON.stringify({ pin: '123456' }),
  });
  const savedBody = await saved.json();
  assert.equal(saved.status, 200);
  assert.equal(savedBody.user.hasPin, true);
  assert.notEqual(users.get('1').pinHash, '123456');

  const pinLogin = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pin: '123456' }),
  });
  const pinSession = await pinLogin.json();
  assert.equal(pinLogin.status, 200);
  assert.equal(pinSession.user.hasPin, true);

  const wrongPin = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pin: '654321' }),
  });
  assert.equal(wrongPin.status, 401);

  const profileResponse = await fetch(`${baseUrl}/me`, {
    headers: { Authorization: `Bearer ${pinSession.token}` },
  });
  const profile = await profileResponse.json();
  assert.equal(profile.user.hasPin, true);
});
