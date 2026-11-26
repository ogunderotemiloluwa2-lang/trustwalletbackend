const mongoose = require('mongoose');

mongoose.set('sanitizeFilter', true);

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      trim: true,
      maxlength: 80,
      default: '',
    },
    passwordHash: {
      type: String,
      required: true,
      select: false,
    },
    // Keyed digest of the wallet password. It lets a sign-in find the account
    // without an email address while still requiring the bcrypt comparison
    // below, and it cannot be enumerated from a database dump alone because the
    // digest is keyed with the server secret.
    passwordLookup: {
      type: String,
      required: true,
      select: false,
      index: true,
    },
    // Six-digit code used to sign in after the wallet has been created. Stored
    // as a bcrypt hash and never returned to the client.
    pinHash: {
      type: String,
      select: false,
      default: null,
    },
    pinLookup: {
      type: String,
      select: false,
      default: null,
      index: true,
    },
    // Headline portfolio balance for the account, in USD. It is stored on the
    // account so every device shows the same amount and signing out or removing
    // the wallet from a device never resets it.
    balance: {
      type: Number,
      default: 0,
      min: 0,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.models.User || mongoose.model('User', userSchema);
