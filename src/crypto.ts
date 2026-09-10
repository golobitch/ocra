import { TOTPError } from "./errors.js";
import type { Algorithm, AlgorithmInput } from "./types.js";

const ALGORITHMS: Record<string, Algorithm> = {
  "SHA-1": "SHA-1",
  SHA1: "SHA-1",
  "SHA-256": "SHA-256",
  SHA256: "SHA-256",
  "SHA-512": "SHA-512",
  SHA512: "SHA-512",
};

/**
 * Maps any accepted spelling of an algorithm onto its WebCrypto name.
 *
 * Accepts a bare `string` so it can validate values arriving from outside the
 * type system, such as an `algorithm` parameter parsed out of an otpauth URI.
 *
 * @throws {TOTPError} `INVALID_ALGORITHM` for anything else.
 */
export function normalizeAlgorithm(algorithm: AlgorithmInput | string): Algorithm {
  const normalized = ALGORITHMS[String(algorithm).toUpperCase()];
  if (!normalized) {
    throw new TOTPError(
      "INVALID_ALGORITHM",
      `Unsupported algorithm ${JSON.stringify(algorithm)}. Expected SHA-1, SHA-256 or SHA-512.`,
    );
  }
  return normalized;
}

function getCrypto(): Crypto {
  const webcrypto = globalThis.crypto;
  if (!webcrypto?.subtle) {
    throw new TOTPError(
      "CRYPTO_UNAVAILABLE",
      "globalThis.crypto.subtle is unavailable. This package requires a WebCrypto implementation (Node 18+, Deno, Bun, browsers or edge runtimes).",
    );
  }
  return webcrypto;
}

/** Computes `HMAC(key, message)` with the given hash. */
export async function hmac(
  algorithm: Algorithm,
  key: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array> {
  const subtle = getCrypto().subtle;
  const cryptoKey = await subtle.importKey(
    "raw",
    toArrayBuffer(key),
    { name: "HMAC", hash: algorithm },
    false,
    ["sign"],
  );
  const signature = await subtle.sign("HMAC", cryptoKey, toArrayBuffer(message));
  return new Uint8Array(signature);
}

/** Computes a plain hash of `message`. */
export async function digest(algorithm: Algorithm, message: Uint8Array): Promise<Uint8Array> {
  const hashed = await getCrypto().subtle.digest(algorithm, toArrayBuffer(message));
  return new Uint8Array(hashed);
}

/** Fills a buffer of `size` bytes from the platform CSPRNG. */
export function randomBytes(size: number): Uint8Array {
  const bytes = new Uint8Array(size);
  getCrypto().getRandomValues(bytes);
  return bytes;
}

/**
 * Compares two strings without leaking, through timing, how far they matched.
 *
 * Lengths are compared eagerly; only the code digits are secret here, and every
 * caller in this package compares codes of equal, publicly known length.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Copies into a standalone `ArrayBuffer`.
 *
 * A `Uint8Array` may be a view onto a larger buffer (Node's `Buffer` pools
 * allocations, so this is the common case), and handing WebCrypto the whole
 * backing buffer would sign the wrong bytes.
 */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}
