import { timingSafeEqual } from "./crypto.js";
import { TOTPError } from "./errors.js";
import { generateHOTP, validateDigits, validateWindow } from "./hotp.js";
import type { AlgorithmInput, Secret } from "./types.js";

export interface TOTPOptions {
  /** Shared secret: raw bytes, or a base32 string as shown by authenticator apps. */
  secret: Secret;
  /** Code length. @defaultValue 6 */
  digits?: number;
  /** Length of one time step, in seconds (RFC 6238 `X`). @defaultValue 30 */
  period?: number;
  /** HMAC hash. @defaultValue "SHA-1" */
  algorithm?: AlgorithmInput;
  /**
   * Point in time to generate for, as a `Date` or Unix milliseconds.
   * @defaultValue `Date.now()`
   */
  timestamp?: number | Date;
  /**
   * Start of the counting epoch (RFC 6238 `T0`), in Unix milliseconds.
   * @defaultValue 0
   */
  epoch?: number;
}

export interface VerifyTOTPOptions extends TOTPOptions {
  /** The code supplied by the user. */
  token: string;
  /**
   * How many time steps on either side of the current one to also accept,
   * absorbing clock drift and the time the user spends typing. A window of `1`
   * with the default period accepts codes up to 30s old or 30s early.
   * @defaultValue 1
   */
  window?: number;
}

/**
 * Generates an RFC 6238 TOTP code.
 *
 * @example
 * ```ts
 * const code = await generateTOTP({ secret: "JBSWY3DPEHPK3PXP" });
 * ```
 */
export async function generateTOTP(options: TOTPOptions): Promise<string> {
  return generateHOTP({
    secret: options.secret,
    counter: totpCounter(options),
    digits: options.digits ?? 6,
    algorithm: options.algorithm ?? "SHA-1",
  });
}

/**
 * Verifies a TOTP code against the current time step and the `window` steps on
 * either side of it.
 *
 * Returns the offset in time steps at which the code matched — `0` for the
 * current step, negative for a code from the past, positive for one from a
 * clock running ahead — or `null` if none matched.
 *
 * The offset is worth persisting: a repeat of a `delta` you have already
 * accepted is a replayed code, and a consistent non-zero offset means the
 * user's device clock has drifted.
 */
export async function verifyTOTPDelta(options: VerifyTOTPOptions): Promise<number | null> {
  const { token, window = 1, ...rest } = options;
  const digits = validateDigits(rest.digits ?? 6);
  validateWindow(window);
  const counter = totpCounter(rest);

  if (typeof token !== "string" || token.length !== digits) return null;

  // Nearest first: the current step is overwhelmingly the common case.
  for (const delta of searchOrder(window)) {
    const candidate = counter + BigInt(delta);
    if (candidate < 0n) continue;

    const expected = await generateHOTP({
      secret: rest.secret,
      counter: candidate,
      digits,
      algorithm: rest.algorithm ?? "SHA-1",
    });
    if (timingSafeEqual(expected, token)) return delta;
  }

  return null;
}

/**
 * Verifies a TOTP code.
 *
 * @example
 * ```ts
 * if (await verifyTOTP({ secret, token: submitted })) {
 *   // accepted
 * }
 * ```
 */
export async function verifyTOTP(options: VerifyTOTPOptions): Promise<boolean> {
  return (await verifyTOTPDelta(options)) !== null;
}

/**
 * Computes the time-step counter `T` that {@link generateTOTP} would use.
 *
 * @throws {TOTPError} `INVALID_PERIOD` for a non-positive period, or if the
 * timestamp falls before `epoch`.
 */
export function totpCounter(options: Pick<TOTPOptions, "period" | "timestamp" | "epoch">): bigint {
  const period = validatePeriod(options.period ?? 30);
  const timestamp = resolveTimestamp(options.timestamp);
  const epoch = options.epoch ?? 0;

  const elapsed = Math.floor(timestamp / 1000) - Math.floor(epoch / 1000);
  if (elapsed < 0) {
    throw new TOTPError("INVALID_PERIOD", "timestamp must not fall before epoch.");
  }
  return BigInt(Math.floor(elapsed / period));
}

/**
 * Milliseconds until the current code expires, for rendering a countdown.
 *
 * @example
 * ```ts
 * const ms = timeRemaining({ period: 30 }); // 0 < ms <= 30_000
 * ```
 */
export function timeRemaining(
  options: Pick<TOTPOptions, "period" | "timestamp" | "epoch"> = {},
): number {
  const period = validatePeriod(options.period ?? 30);
  const timestamp = resolveTimestamp(options.timestamp);
  const epoch = options.epoch ?? 0;

  const elapsed = timestamp - epoch;
  const periodMs = period * 1000;
  return periodMs - (((elapsed % periodMs) + periodMs) % periodMs);
}

function validatePeriod(period: number): number {
  if (!Number.isInteger(period) || period <= 0) {
    throw new TOTPError("INVALID_PERIOD", `period must be a positive integer, received ${period}.`);
  }
  return period;
}

function resolveTimestamp(timestamp: number | Date | undefined): number {
  if (timestamp === undefined) return Date.now();
  const value = timestamp instanceof Date ? timestamp.getTime() : timestamp;
  if (!Number.isFinite(value)) {
    throw new TOTPError("INVALID_PERIOD", `timestamp must be a finite number or Date, received ${timestamp}.`);
  }
  return value;
}

/** `0, -1, +1, -2, +2, …` up to `±window`. */
function searchOrder(window: number): number[] {
  const order = [0];
  for (let i = 1; i <= window; i++) order.push(-i, i);
  return order;
}
