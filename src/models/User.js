const mongoose = require('mongoose');

mongoose.set('sanitizeFilter', true);

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
      unique: true,
      maxlength: 254,
      match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    },
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
    // Six-digit code used to sign in after the wallet has been created. Stored
    // as a bcrypt hash and never returned to the client.
    pinHash: {
      type: String,
      select: false,
      default: null,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.models.User || mongoose.model('User', userSchema);
