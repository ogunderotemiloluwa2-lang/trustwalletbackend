const express = require('express');
const cors = require('cors');
const User = require('./models/User');
const Wallet = require('./models/Wallet');
const { createAuthRouter } = require('./auth');
const { createWalletRouter } = require('./wallets');

const DEFAULT_ALLOWED_ORIGINS = ['http://localhost:3000'];

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

const createApp = ({ jwtSecret, UserModel = User, WalletModel = Wallet, allowedOrigins } = {}) => {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  app.use(
    cors({
      origin: parseAllowedOrigins(allowedOrigins),
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
      return response.status(409).json({ error: 'An account with this email already exists.' });
    }
    console.error('API request failed:', error);
    return response.status(500).json({ error: 'The request could not be completed.' });
  });
  return app;
};

module.exports = { createApp, parseAllowedOrigins };
