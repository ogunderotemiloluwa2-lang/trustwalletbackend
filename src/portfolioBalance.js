/**
 * Headline portfolio balance helpers.
 *
 * The balance is a plain USD amount owned by the account. It lives on the user
 * document so it survives signing out, switching devices, and removing a
 * wallet from the device.
 */
const MAX_BALANCE = 1_000_000_000_000;

/**
 * Normalises a balance sent by the client. Returns `null` for anything that is
 * not a finite, non-negative number so the route can reject it.
 */
const parseBalance = (value) => {
  const amount = typeof value === 'string' ? Number(value.trim()) : value;
  if (typeof amount !== 'number' || !Number.isFinite(amount) || amount < 0) return null;
  return Math.min(amount, MAX_BALANCE);
};

module.exports = { MAX_BALANCE, parseBalance };
