/**
 * Demo portfolio balance spec.
 *
 * The wallet shows a headline balance that starts at a fixed amount and grows
 * by a fixed percentage on a fixed interval, but only on working days
 * (Monday to Friday). The compact format is `<amount>,<interval>,<rate>`:
 *
 *   '20k,1min,3%'   -> $20,000 growing 3% every 1 minute
 *   '40k,5mins,2%'  -> $40,000 growing 2% every 5 minutes
 *   '1.5m,30s,0.5%' -> $1,500,000 growing 0.5% every 30 seconds
 */
const DEMO_PORTFOLIO_SPEC = '20k,1min,3%';

const AMOUNT_PATTERN = /^(\d+(?:\.\d+)?)\s*([km])?$/i;
const INTERVAL_PATTERN = /^(\d+(?:\.\d+)?)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours)$/i;
const RATE_PATTERN = /^(\d+(?:\.\d+)?)\s*%$/;

const AMOUNT_SUFFIXES = { k: 1_000, m: 1_000_000 };
const INTERVAL_UNITS = {
  s: 1_000, sec: 1_000, secs: 1_000, second: 1_000, seconds: 1_000,
  m: 60_000, min: 60_000, mins: 60_000, minute: 60_000, minutes: 60_000,
  h: 3_600_000, hr: 3_600_000, hrs: 3_600_000, hour: 3_600_000, hours: 3_600_000,
};

/** Returns the parsed spec, or `null` when the text is not a valid spec. */
const parseDemoPortfolioSpec = (spec) => {
  if (typeof spec !== 'string') return null;
  const parts = spec.split(',').map((part) => part.trim());
  if (parts.length !== 3) return null;

  const amountMatch = AMOUNT_PATTERN.exec(parts[0]);
  const intervalMatch = INTERVAL_PATTERN.exec(parts[1]);
  const rateMatch = RATE_PATTERN.exec(parts[2]);
  if (!amountMatch || !intervalMatch || !rateMatch) return null;

  const baseAmount = Number(amountMatch[1]) * (AMOUNT_SUFFIXES[(amountMatch[2] || '').toLowerCase()] || 1);
  const intervalMs = Number(intervalMatch[1]) * INTERVAL_UNITS[intervalMatch[2].toLowerCase()];
  const ratePerInterval = Number(rateMatch[1]) / 100;

  if (!Number.isFinite(baseAmount) || baseAmount <= 0) return null;
  if (!Number.isFinite(intervalMs) || intervalMs <= 0) return null;
  if (!Number.isFinite(ratePerInterval) || ratePerInterval <= 0) return null;

  return { baseAmount, intervalMs, ratePerInterval };
};

module.exports = { DEMO_PORTFOLIO_SPEC, parseDemoPortfolioSpec };
