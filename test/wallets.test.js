const assert = require('node:assert/strict');
const { after, before, test } = require('node:test');
const express = require('express');
const { createToken } = require('../src/auth');
const { createWalletRouter, sanitizeAddresses } = require('../src/wallets');
const WalletSchemaModel = require('../src/models/Wallet');

const JWT_SECRET = 'test-secret-with-more-than-thirty-two-characters';
const USER_ID = '507f1f77bcf86cd799439011';

const users = new Map([[USER_ID, {
  _id: USER_ID,
  name: 'Person',
  async save() { return this; },
}]]);
const User = {
  async findById(id) {
    return users.get(String(id)) || null;
  },
};

const wallets = [];
const Wallet = {
  async findOneAndUpdate(filter, update, options) {
    const existing = wallets.find(
      (wallet) => String(wallet.user) === String(filter.user) && wallet.address === filter.address
    );
    if (existing) {
      Object.assign(existing, update.$set);
      return existing;
    }
    const created = {
      _id: String(wallets.length + 1),
      user: filter.user,
      address: filter.address,
      ...update.$set,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    wallets.push(created);
    return created;
  },
  find({ user }) {
    return {
      sort: async () => wallets.filter((wallet) => String(wallet.user) === String(user)),
    };
  },
};

const app = express();
app.use(express.json());
app.use('/api/wallets', createWalletRouter({ Wallet, User, jwtSecret: JWT_SECRET }));
let server;
let baseUrl;

const authHeaders = () => ({
  'Content-Type': 'application/json',
  Authorization: `Bearer ${createToken(USER_ID, JWT_SECRET)}`,
});

before(async () => {
  server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}/api/wallets`;
});

after(async () => {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

test('validates the wallet schema fields', async () => {
  assert.equal(WalletSchemaModel.schema.path('address').options.required, true);
  await assert.rejects(
    new WalletSchemaModel({ user: USER_ID }).validate(),
    { name: 'ValidationError' }
  );
});

test('drops malformed entries from the address map', () => {
  const sanitized = sanitizeAddresses({
    ethereum: '0xabc',
    bitcoin: 'bc1qexample',
    'bad key!': '0xdead',
    empty: '   ',
    numeric: 42,
  });
  assert.deepEqual(sanitized, { ethereum: '0xabc', bitcoin: 'bc1qexample' });
  assert.deepEqual(sanitizeAddresses(null), {});
  assert.deepEqual(sanitizeAddresses(['ethereum']), {});
});

test('rejects wallet requests without a valid token', async () => {
  const response = await fetch(baseUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ address: '0xabc' }),
  });
  assert.equal(response.status, 401);
});

test('saves a wallet for the signed-in account and lists it back', async () => {
  const createResponse = await fetch(baseUrl, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({
      address: '0x1234567890abcdef',
      label: 'My wallet',
      source: 'created',
      addresses: { ethereum: '0x1234567890abcdef', bitcoin: 'bc1qexample' },
    }),
  });
  const created = await createResponse.json();

  assert.equal(createResponse.status, 201);
  assert.equal(created.wallet.address, '0x1234567890abcdef');
  assert.equal(created.wallet.addresses.bitcoin, 'bc1qexample');

  const listResponse = await fetch(baseUrl, { headers: authHeaders() });
  const listed = await listResponse.json();
  assert.equal(listResponse.status, 200);
  assert.equal(listed.wallets.length, 1);
  assert.equal(listed.wallets[0].address, '0x1234567890abcdef');
});

test('upserts instead of duplicating the same wallet address', async () => {
  const response = await fetch(baseUrl, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ address: '0x1234567890abcdef', label: 'Renamed', source: 'imported' }),
  });
  const data = await response.json();

  assert.equal(response.status, 201);
  assert.equal(data.wallet.label, 'Renamed');
  assert.equal(data.wallet.source, 'imported');
  assert.equal(wallets.length, 1);
});

test('rejects a wallet without an address', async () => {
  const response = await fetch(baseUrl, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ label: 'No address' }),
  });
  assert.equal(response.status, 400);
});

test('stores the wallet owner name and network, and mirrors the name onto the account', async () => {
  const response = await fetch(baseUrl, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({
      address: '0xfeedface',
      ownerName: 'Ada Lovelace',
      network: 'bitcoin',
      source: 'created',
    }),
  });
  const data = await response.json();

  assert.equal(response.status, 201);
  assert.equal(data.wallet.ownerName, 'Ada Lovelace');
  assert.equal(data.wallet.network, 'bitcoin');
  assert.equal(users.get(USER_ID).name, 'Ada Lovelace');
});
