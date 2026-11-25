const mongoose = require('mongoose');

/**
 * Wallet metadata created during onboarding. Only public information is stored:
 * the encrypted keystore and the recovery phrase never leave the browser.
 */
const walletSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    label: {
      type: String,
      trim: true,
      maxlength: 80,
      default: 'My wallet',
    },
    // Name the user entered while creating the wallet, kept with the wallet so
    // the account identity is owned by the wallet rather than a separate signup.
    ownerName: {
      type: String,
      trim: true,
      maxlength: 80,
      default: '',
    },
    address: {
      type: String,
      required: true,
      trim: true,
      maxlength: 128,
    },
    source: {
      type: String,
      enum: ['created', 'imported'],
      default: 'created',
    },
    network: {
      type: String,
      trim: true,
      maxlength: 40,
      default: 'ethereum',
    },
    addresses: {
      type: Map,
      of: { type: String, trim: true, maxlength: 128 },
      default: {},
    },
  },
  { timestamps: true }
);

walletSchema.index({ user: 1, address: 1 }, { unique: true });

module.exports = mongoose.models.Wallet || mongoose.model('Wallet', walletSchema);
