const express = require('express');
const { verifyToken } = require('./auth');

const MAX_ADDRESSES = 40;
const ADDRESS_KEY_PATTERN = /^[a-zA-Z0-9_-]{1,40}$/;

const asyncRoute = (handler) => (request, response, next) => {
  Promise.resolve(handler(request, response, next)).catch(next);
};

const toWallet = (wallet) => {
  const addresses = wallet.addresses instanceof Map
    ? Object.fromEntries(wallet.addresses)
    : (wallet.addresses && typeof wallet.addresses === 'object' ? { ...wallet.addresses } : {});
  return {
    id: String(wallet._id),
    label: wallet.label || 'My wallet',
    ownerName: wallet.ownerName || '',
    address: wallet.address,
    source: wallet.source || 'created',
    network: wallet.network || 'ethereum',
    addresses,
    createdAt: wallet.createdAt,
    updatedAt: wallet.updatedAt,
  };
};

/**
 * Normalises the per-network address map sent by the client, dropping anything
 * that is not a short string so a malformed payload cannot bloat the document.
 */
const sanitizeAddresses = (value) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const entries = Object.entries(value)
    .filter(([key, address]) =>
      ADDRESS_KEY_PATTERN.test(key) && typeof address === 'string' && address.trim().length > 0
    )
    .slice(0, MAX_ADDRESSES)
    .map(([key, address]) => [key, address.trim().slice(0, 128)]);
  return Object.fromEntries(entries);
};

const createWalletRouter = ({ Wallet, User, jwtSecret, now = Date.now }) => {
  if (!Wallet) throw new Error('A wallet model is required to create the wallet routes.');
  if (!jwtSecret) throw new Error('JWT_SECRET is required to create the wallet routes.');

  const router = express.Router();

  const requireUser = asyncRoute(async (request, response, next) => {
    const authorization = request.get('authorization') || '';
    const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
    const payload = verifyToken(token, jwtSecret, now());
    if (!payload) return response.status(401).json({ error: 'Authentication required.' });

    const user = await User.findById(payload.sub);
    if (!user) return response.status(401).json({ error: 'Authentication required.' });
    request.user = user;
    return next();
  });

  router.use(requireUser);

  // Upserts the wallet record for the signed-in account so onboarding is
  // idempotent when the same wallet is saved again.
  router.post('/', asyncRoute(async (request, response) => {
    const body = request.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return response.status(400).json({ error: 'Request body must be an object.' });
    }
    const address = typeof body.address === 'string' ? body.address.trim() : '';
    if (!address || address.length > 128) {
      return response.status(400).json({ error: 'A wallet address is required.' });
    }
    const label = typeof body.label === 'string' && body.label.trim()
      ? body.label.trim().slice(0, 80)
      : 'My wallet';
    const ownerName = typeof body.ownerName === 'string' ? body.ownerName.trim().slice(0, 80) : '';
    const source = body.source === 'imported' ? 'imported' : 'created';
    const network = typeof body.network === 'string' && body.network.trim()
      ? body.network.trim().slice(0, 40)
      : 'ethereum';

    const wallet = await Wallet.findOneAndUpdate(
      { user: request.user._id, address },
      { $set: { label, ownerName, source, network, addresses: sanitizeAddresses(body.addresses) } },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );

    // The wallet owns the account identity, so the name entered during wallet
    // creation is mirrored onto the user profile.
    if (ownerName && request.user.name !== ownerName) {
      request.user.name = ownerName;
      await request.user.save();
    }

    return response.status(201).json({ wallet: toWallet(wallet) });
  }));

  router.get('/', asyncRoute(async (request, response) => {
    const wallets = await Wallet.find({ user: request.user._id }).sort({ createdAt: 1 });
    return response.json({ wallets: wallets.map(toWallet) });
  }));

  return router;
};

module.exports = { createWalletRouter, sanitizeAddresses };
