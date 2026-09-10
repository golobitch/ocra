import { hmac, normalizeAlgorithm, timingSafeEqual } from "./crypto.js";
import { base32Decode } from "./encoding.js";
import { TOTPError } from "./errors.js";
import type { AlgorithmInput, Secret } from "./types.js";

/** Smallest and largest code length this package will produce. */
const MIN_DIGITS = 1;
const MAX_DIGITS = 10;

/** Largest counter an unsigned 64-bit field can hold. */
const MAX_COUNTER = 2n ** 64n - 1n;

export interface HOTPOptions {
  /** Shared secret: raw bytes, or a base32 string as shown by authenticator apps. */
  secret: Secret;
  /** Moving factor. Accepts a `number` or, for very large counters, a `bigint`. */
  counter: number | bigint;
  /** Code length. RFC 4226 requires at least 6. @defaultValue 6 */
  digits?: number;
  /** HMAC hash. @defaultValue "SHA-1" */
  algorithm?: AlgorithmInput;
}

export interface VerifyHOTPOptions extends Omit<HOTPOptions, "counter"> {
  /** The code supplied by the user. */
  token: string;
  /** Counter value expected next for this user. */
  counter: number | bigint;
  /**
   * How many counter values past `counter` to also accept, to resynchronize
   * after the user generated codes that were never submitted.
   * @defaultValue 0
   */
  window?: number;
}

/**
 * Generates an RFC 4226 HOTP code.
 *
 * @example
 * ```ts
 * await generateHOTP({ secret: "JBSWY3DPEHPK3PXP", counter: 0 }); // "282760"
 * ```
 */
export async function generateHOTP(options: HOTPOptions): Promise<string> {
  const secret = normalizeSecret(options.secret);
  const digits = validateDigits(options.digits ?? 6);
  const algorithm = normalizeAlgorithm(options.algorithm ?? "SHA-1");
  const counter = validateCounter(options.counter);

  const digest = await hmac(algorithm, secret, encodeCounter(counter));
  return truncate(digest, digits);
}

/**
 * Verifies an HOTP code against `counter`, and against the next `window`
 * counters after it.
 *
 * Returns how far ahead the match was — `0` for an exact match — or `null` if
 * no counter in the range produced the code. Persist `counter + delta + 1` as
 * the user's next expected counter so a code can never be replayed.
 */
export async function verifyHOTPDelta(options: VerifyHOTPOptions): Promise<number | null> {
  const { token, counter, window = 0, ...rest } = options;
  const digits = validateDigits(rest.digits ?? 6);
  const start = validateCounter(counter);
  validateWindow(window);

  if (!isPlausibleToken(token, digits)) return null;

  for (let delta = 0; delta <= window; delta++) {
    const candidate = await generateHOTP({ ...rest, digits, counter: start + BigInt(delta) });
    if (timingSafeEqual(candidate, token)) return delta;
  }

  return null;
}

/**
 * Verifies an HOTP code.
 *
 * Prefer {@link verifyHOTPDelta} when you store the counter, so you can advance
 * it past the code that was just used.
 */
export async function verifyHOTP(options: VerifyHOTPOptions): Promise<boolean> {
  return (await verifyHOTPDelta(options)) !== null;
}

/**
 * RFC 4226 §5.3 dynamic truncation: take the low nibble of the last byte as an
 * offset, read the 31-bit big-endian integer there, and reduce it to `digits`.
 */
export function truncate(digest: Uint8Array, digits: number): string {
  const offset = (digest[digest.length - 1] as number) & 0x0f;
  const binary =
    (((digest[offset] as number) & 0x7f) << 24) |
    ((digest[offset + 1] as number) << 16) |
    ((digest[offset + 2] as number) << 8) |
    (digest[offset + 3] as number);

  return (binary % 10 ** digits).toString().padStart(digits, "0");
}

/** Serializes a counter as the 8-byte big-endian message RFC 4226 signs. */
export function encodeCounter(counter: bigint): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, counter, false);
  return bytes;
}

/** Resolves a secret to bytes, decoding base32 when given a string. */
export function normalizeSecret(secret: Secret): Uint8Array {
  const bytes = typeof secret === "string" ? base32Decode(secret) : secret;
  if (!(bytes instanceof Uint8Array)) {
    throw new TOTPError("INVALID_SECRET", "Secret must be a Uint8Array or a base32 string.");
  }
  if (bytes.length === 0) {
    throw new TOTPError("INVALID_SECRET", "Secret must not be empty.");
  }
  return bytes;
}

export function validateDigits(digits: number): number {
  if (!Number.isInteger(digits) || digits < MIN_DIGITS || digits > MAX_DIGITS) {
    throw new TOTPError(
      "INVALID_DIGITS",
      `digits must be an integer between ${MIN_DIGITS} and ${MAX_DIGITS}, received ${digits}.`,
    );
  }
  return digits;
}

export function validateWindow(window: number): number {
  if (!Number.isInteger(window) || window < 0) {
    throw new TOTPError("INVALID_WINDOW", `window must be a non-negative integer, received ${window}.`);
  }
  return window;
}

function validateCounter(counter: number | bigint): bigint {
  if (typeof counter === "number" && !Number.isSafeInteger(counter)) {
    throw new TOTPError(
      "INVALID_COUNTER",
      `counter must be a safe integer or a bigint, received ${counter}.`,
    );
  }
  const value = BigInt(counter);
  if (value < 0n || value > MAX_COUNTER) {
    throw new TOTPError("INVALID_COUNTER", `counter must fit in an unsigned 64-bit integer, received ${counter}.`);
  }
  return value;
}

/**
 * Cheap shape check before doing any HMAC work, so a malformed submission
 * cannot be used to make the server hash `window + 1` times.
 */
function isPlausibleToken(token: string, digits: number): boolean {
  return typeof token === "string" && token.length === digits;
}
