const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const { parseBalance } = require('./portfolioBalance');

const TOKEN_LIFETIME_SECONDS = 60 * 60;
const PASSWORD_HASH_COST = 12;
const PIN_PATTERN = /^\d{6}$/;
const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_BYTES = 72;

const encodeTokenPart = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

const createToken = (userId, secret, now = Date.now()) => {
  const issuedAt = Math.floor(now / 1000);
  const header = encodeTokenPart({ alg: 'HS256', typ: 'JWT' });
  const payload = encodeTokenPart({
    sub: String(userId),
    iat: issuedAt,
    exp: issuedAt + TOKEN_LIFETIME_SECONDS,
  });
  const content = `${header}.${payload}`;
  const signature = crypto.createHmac('sha256', secret).update(content).digest('base64url');
  return `${content}.${signature}`;
};

const verifyToken = (token, secret, now = Date.now()) => {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [headerPart, payloadPart, signaturePart] = parts;
  const content = `${headerPart}.${payloadPart}`;
  const expected = crypto.createHmac('sha256', secret).update(content).digest();
  let actual;
  try {
    actual = Buffer.from(signaturePart, 'base64url');
  } catch {
    return null;
  }
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;

  try {
    const header = JSON.parse(Buffer.from(headerPart, 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf8'));
    if (header.alg !== 'HS256' || typeof payload.sub !== 'string' ||
        typeof payload.exp !== 'number' || payload.exp <= Math.floor(now / 1000)) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
};

/**
 * Keyed digest used to look an account up without an email address. The digest
 * is scoped per credential type so a password can never collide with a code.
 */
const credentialLookup = (secret, scope, value) =>
  crypto.createHmac('sha256', secret).update(`${scope}:${value}`).digest('hex');

const toProfile = (user) => ({
  id: String(user._id),
  name: user.name || '',
  hasPin: Boolean(user.pinHash),
  balance: Number.isFinite(user.balance) ? user.balance : 0,
});

const asyncRoute = (handler) => (request, response, next) => {
  Promise.resolve(handler(request, response, next)).catch(next);
};

const readBearerToken = (request) => {
  const authorization = request.get('authorization') || '';
  return authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
};

const createAuthRouter = ({ User, jwtSecret, now = Date.now }) => {
  if (!User) throw new Error('A user model is required to create the authentication routes.');
  if (!jwtSecret) throw new Error('JWT_SECRET is required to create the authentication routes.');

  const router = express.Router();

  router.post('/register', asyncRoute(async (request, response) => {
    const body = request.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return response.status(400).json({ error: 'Request body must be an object.' });
    }
    const password = typeof body.password === 'string' ? body.password : '';
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    const passwordBytes = Buffer.byteLength(password, 'utf8');
    if (password.length < MIN_PASSWORD_LENGTH || passwordBytes > MAX_PASSWORD_BYTES) {
      return response.status(400).json({ error: 'Password must contain at least 8 characters and no more than 72 UTF-8 bytes.' });
    }
    if (name.length > 80) {
      return response.status(400).json({ error: 'Name must be 80 characters or fewer.' });
    }

    const passwordHash = await bcrypt.hash(password, PASSWORD_HASH_COST);
    const user = await User.create({
      name,
      passwordHash,
      passwordLookup: credentialLookup(jwtSecret, 'password', password),
    });
    return response.status(201).json({
      token: createToken(user._id, jwtSecret, now()),
      user: toProfile(user),
    });
  }));

  // Sign-in accepts either the six-digit code chosen during wallet setup or the
  // wallet password, which is the fallback when the code is forgotten. The
  // account is identified by the credential itself, so no email is needed.
  router.post('/login', asyncRoute(async (request, response) => {
    const body = request.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return response.status(400).json({ error: 'Enter your six-digit code or wallet password.' });
    }
    const password = typeof body.password === 'string' ? body.password : '';
    const pin = typeof body.pin === 'string' ? body.pin.trim() : '';
    if (!password && !pin) {
      return response.status(400).json({ error: 'Enter your six-digit code or wallet password.' });
    }
    if (pin && !PIN_PATTERN.test(pin)) {
      return response.status(400).json({ error: 'Enter the six-digit code.' });
    }
    if (Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES) {
      return response.status(400).json({ error: 'Enter your six-digit code or wallet password.' });
    }

    const user = pin
      ? await User.findOne({ pinLookup: credentialLookup(jwtSecret, 'pin', pin) }).select('+passwordHash +pinHash')
      : await User.findOne({ passwordLookup: credentialLookup(jwtSecret, 'password', password) })
        .select('+passwordHash +pinHash');
    const authenticated = user && (pin
      ? Boolean(user.pinHash) && (await bcrypt.compare(pin, user.pinHash))
      : await bcrypt.compare(password, user.passwordHash));
    if (!authenticated) {
      return response.status(401).json({
        error: pin ? 'That six-digit code is not recognised.' : 'That wallet password is not recognised.',
      });
    }
    return response.json({
      token: createToken(user._id, jwtSecret, now()),
      user: toProfile(user),
    });
  }));

  // Stores the six-digit code that replaces the password for future sign-ins.
  router.post('/pin', asyncRoute(async (request, response) => {
    const payload = verifyToken(readBearerToken(request), jwtSecret, now());
    if (!payload) return response.status(401).json({ error: 'Authentication required.' });

    const body = request.body;
    const pin = body && typeof body.pin === 'string' ? body.pin.trim() : '';
    if (!PIN_PATTERN.test(pin)) {
      return response.status(400).json({ error: 'Choose a six-digit code.' });
    }

    const user = await User.findById(payload.sub);
    if (!user) return response.status(401).json({ error: 'Authentication required.' });
    user.pinHash = await bcrypt.hash(pin, PASSWORD_HASH_COST);
    user.pinLookup = credentialLookup(jwtSecret, 'pin', pin);
    await user.save();
    return response.json({ user: toProfile(user) });
  }));

  router.get('/me', asyncRoute(async (request, response) => {
    const payload = verifyToken(readBearerToken(request), jwtSecret, now());
    if (!payload) return response.status(401).json({ error: 'Authentication required.' });

    const user = await User.findById(payload.sub).select('+pinHash');
    if (!user) return response.status(401).json({ error: 'Authentication required.' });
    return response.json({ user: toProfile(user) });
  }));

  // Stores the headline balance on the account so every device shows the same
  // amount and signing out or removing the wallet never resets it.
  router.post('/balance', asyncRoute(async (request, response) => {
    const payload = verifyToken(readBearerToken(request), jwtSecret, now());
    if (!payload) return response.status(401).json({ error: 'Authentication required.' });

    const body = request.body;
    const amount = parseBalance(body && body.balance);
    if (amount === null) {
      return response.status(400).json({ error: 'Balance must be a number of 0 or more.' });
    }

    const user = await User.findById(payload.sub);
    if (!user) return response.status(401).json({ error: 'Authentication required.' });
    user.balance = amount;
    await user.save();
    return response.json({ user: toProfile(user) });
  }));

  return router;
};

module.exports = { createAuthRouter, createToken, verifyToken, credentialLookup };
