const express = require('express');
const cors = require('cors');
const User = require('./models/User');
const Wallet = require('./models/Wallet');
const { createAuthRouter } = require('./auth');
const { createWalletRouter } = require('./wallets');

const DEFAULT_ALLOWED_ORIGINS = ['http://localhost:3000', 'http://localhost:5173'];

/**
 * Vercel serves the frontend from a generated `*.vercel.app` domain, and every
 * preview deployment gets its own hostname. Matching the whole domain keeps the
 * deployed frontend working without having to redeploy the API for each preview.
 */
const VERCEL_ORIGIN_PATTERN = /^https:\/\/[a-z0-9-]+(\.[a-z0-9-]+)*\.vercel\.app$/i;

/**
 * Parses CORS_ORIGIN into a list. Accepts a comma-separated string so a single
 * Render environment variable can cover the Vercel production domain plus any
 * preview or localhost origins.
 */
const parseAllowedOrigins = (value) => {
  if (!value) return DEFAULT_ALLOWED_ORIGINS;
  const origins = value
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
  return origins.length > 0 ? origins : DEFAULT_ALLOWED_ORIGINS;
};

/**
 * Decides whether a browser origin may call the API. Requests without an Origin
 * header (health checks, curl, server-to-server) are always allowed.
 */
const createOriginCheck = (allowedOrigins) => {
  const origins = parseAllowedOrigins(allowedOrigins);
  return (origin, callback) => {
    if (!origin) return callback(null, true);
    if (origins.includes(origin) || VERCEL_ORIGIN_PATTERN.test(origin)) {
      return callback(null, true);
    }
    return callback(null, false);
  };
};

const createApp = ({ jwtSecret, UserModel = User, WalletModel = Wallet, allowedOrigins } = {}) => {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  app.use(
    cors({
      origin: createOriginCheck(allowedOrigins),
      methods: ['GET', 'POST', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      maxAge: 86400,
    })
  );
  app.use(express.json({ limit: '10kb' }));

  // Render health check; also handy for confirming the deployed URL is live.
  app.get('/health', (request, response) => response.json({ status: 'ok' }));

  app.use('/api/auth', createAuthRouter({ User: UserModel, jwtSecret }));
  app.use('/api/wallets', createWalletRouter({ Wallet: WalletModel, User: UserModel, jwtSecret }));

  app.use((request, response) => {
    response.status(404).json({ error: 'Not found.' });
  });

  app.use((error, request, response, next) => {
    if (response.headersSent) return next(error);
    if (error && error.code === 11000) {
      return response.status(409).json({ error: 'That wallet is already registered. Sign in instead.' });
    }
    console.error('API request failed:', error);
    return response.status(500).json({ error: 'The request could not be completed.' });
  });
  return app;
};

module.exports = { createApp, parseAllowedOrigins, createOriginCheck };
