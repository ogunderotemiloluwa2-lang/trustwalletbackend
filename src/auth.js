const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');

const TOKEN_LIFETIME_SECONDS = 60 * 60;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PASSWORD_HASH_COST = 12;
const PIN_PATTERN = /^\d{6}$/;

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

const toProfile = (user) => ({
  id: String(user._id),
  email: user.email,
  name: user.name || '',
  hasPin: Boolean(user.pinHash),
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
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    if (!EMAIL_PATTERN.test(email) || email.length > 254) {
      return response.status(400).json({ error: 'Enter a valid email address.' });
    }
    const passwordBytes = Buffer.byteLength(password, 'utf8');
    if (password.length < 8 || passwordBytes > 72) {
      return response.status(400).json({ error: 'Password must contain at least 8 characters and no more than 72 UTF-8 bytes.' });
    }
    if (name.length > 80) {
      return response.status(400).json({ error: 'Name must be 80 characters or fewer.' });
    }

    const passwordHash = await bcrypt.hash(password, PASSWORD_HASH_COST);
    const user = await User.create({ email, name, passwordHash });
    return response.status(201).json({
      token: createToken(user._id, jwtSecret, now()),
      user: toProfile(user),
    });
  }));

  // Sign-in accepts either the account password or, once a wallet has been
  // created, the six-digit code chosen during wallet setup.
  router.post('/login', asyncRoute(async (request, response) => {
    const body = request.body;
    if (!body || typeof body !== 'object' || Array.isArray(body) ||
        typeof body.email !== 'string') {
      return response.status(400).json({ error: 'Email and password are required.' });
    }
    const email = body.email.trim().toLowerCase();
    const password = typeof body.password === 'string' ? body.password : '';
    const pin = typeof body.pin === 'string' ? body.pin.trim() : '';
    if (!EMAIL_PATTERN.test(email) || (!password && !pin) ||
        Buffer.byteLength(password, 'utf8') > 72) {
      return response.status(400).json({ error: 'Email and password are required.' });
    }
    if (pin && !PIN_PATTERN.test(pin)) {
      return response.status(400).json({ error: 'Enter the six-digit code.' });
    }

    const user = await User.findOne({ email }).select('+passwordHash +pinHash');
    if (!user) {
      return response.status(401).json({ error: 'Invalid email or password.' });
    }
    const authenticated = pin
      ? Boolean(user.pinHash) && (await bcrypt.compare(pin, user.pinHash))
      : await bcrypt.compare(password, user.passwordHash);
    if (!authenticated) {
      return response.status(401).json({
        error: pin ? 'Invalid email or six-digit code.' : 'Invalid email or password.',
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

  return router;
};

module.exports = { createAuthRouter, createToken, verifyToken };
