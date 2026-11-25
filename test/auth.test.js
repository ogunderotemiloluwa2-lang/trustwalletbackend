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
    users.set(user.email, user);
    return user;
  },
  findOne({ email }) {
    return {
      select: async () => users.get(email) || null,
    };
  },
  findById(id) {
    return query([...users.values()].find((user) => user._id === id) || null);
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
  await assert.rejects(
    new UserSchemaModel({ email: 'not-an-email', passwordHash: 'hash' }).validate(),
    { name: 'ValidationError' }
  );
});

test('registers a user with a password hash and returns a profile without the hash', async () => {
  const response = await fetch(`${baseUrl}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'PERSON@example.com', password: 'a secure password', name: 'Person' }),
  });
  const data = await response.json();
  const savedUser = users.get('person@example.com');

  assert.equal(response.status, 201);
  assert.equal(data.user.email, 'person@example.com');
  assert.equal(data.user.name, 'Person');
  assert.equal(Object.hasOwn(data.user, 'passwordHash'), false);
  assert.notEqual(savedUser.passwordHash, 'a secure password');
  assert.equal(await bcrypt.compare('a secure password', savedUser.passwordHash), true);
  assert.equal(typeof data.token, 'string');
});

test('rejects invalid registration input and invalid login credentials', async () => {
  const invalidRegistration = await fetch(`${baseUrl}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'bad', password: 'short' }),
  });
  const invalidLogin = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'person@example.com', password: 'incorrect password' }),
  });

  assert.equal(invalidRegistration.status, 400);
  assert.equal(invalidLogin.status, 401);
});

test('authenticates login and returns the profile from the bearer token', async () => {
  const login = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'person@example.com', password: 'a secure password' }),
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
    email: 'person@example.com',
    name: 'Person',
    hasPin: false,
    demoPortfolioSpec: '',
  });
  assert.equal(unauthenticated.status, 401);
});

test('saves a demo portfolio rule for the signed-in account', async () => {
  const login = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'person@example.com', password: 'a secure password' }),
  });
  const session = await login.json();

  const invalid = await fetch(`${baseUrl}/demo-portfolio`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.token}` },
    body: JSON.stringify({ spec: '40k,5mins' }),
  });
  assert.equal(invalid.status, 400);

  const saved = await fetch(`${baseUrl}/demo-portfolio`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.token}` },
    body: JSON.stringify({ spec: '40k,5mins,2%' }),
  });
  const body = await saved.json();
  assert.equal(saved.status, 200);
  assert.equal(body.user.demoPortfolioSpec, '40k,5mins,2%');

  const profileResponse = await fetch(`${baseUrl}/me`, {
    headers: { Authorization: `Bearer ${session.token}` },
  });
  const profile = await profileResponse.json();
  assert.equal(profile.user.demoPortfolioSpec, '40k,5mins,2%');

  const unauthenticated = await fetch(`${baseUrl}/demo-portfolio`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ spec: '40k,5mins,2%' }),
  });
  assert.equal(unauthenticated.status, 401);
});

test('stores a six-digit code and signs in with it instead of the password', async () => {
  const login = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'person@example.com', password: 'a secure password' }),
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
  assert.notEqual(users.get('person@example.com').pinHash, '123456');

  const pinLogin = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'person@example.com', pin: '123456' }),
  });
  const pinSession = await pinLogin.json();
  assert.equal(pinLogin.status, 200);
  assert.equal(pinSession.user.hasPin, true);

  const wrongPin = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'person@example.com', pin: '654321' }),
  });
  assert.equal(wrongPin.status, 401);

  const profileResponse = await fetch(`${baseUrl}/me`, {
    headers: { Authorization: `Bearer ${pinSession.token}` },
  });
  const profile = await profileResponse.json();
  assert.equal(profile.user.hasPin, true);
});
