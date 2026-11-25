require('dotenv').config();

const mongoose = require('mongoose');
const { createApp } = require('./app');

const start = async () => {
  const { MONGODB_URI, JWT_SECRET, CORS_ORIGIN } = process.env;
  // Render injects PORT; API_PORT is kept as a fallback for local runs where
  // the frontend dev server may already be using PORT.
  const port = Number(process.env.PORT || process.env.API_PORT || 5000);
  if (!MONGODB_URI) throw new Error('MONGODB_URI must be set before starting the API.');
  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must be set to a value of at least 32 characters.');
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('PORT must be a valid TCP port.');
  }

  await mongoose.connect(MONGODB_URI);
  const app = createApp({ jwtSecret: JWT_SECRET, allowedOrigins: CORS_ORIGIN });
  const server = app.listen(port, () => {
    console.log(`Trust Wallet API listening on port ${port}.`);
  });

  const shutdown = async () => {
    server.close(async () => {
      await mongoose.disconnect();
      process.exit(0);
    });
  };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
};

start().catch((error) => {
  console.error('Could not start Trust Wallet API:', error);
  process.exitCode = 1;
});
