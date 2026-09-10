import { normalizeAlgorithm, randomBytes } from "./crypto.js";
import { base32Encode, hexEncode } from "./encoding.js";
import { TOTPError } from "./errors.js";
import type { Algorithm, AlgorithmInput } from "./types.js";

/** Block size of each hash, and so the secret length RFC 4226 §4 R6 recommends. */
const RECOMMENDED_SIZE: Record<Algorithm, number> = {
  "SHA-1": 20,
  "SHA-256": 32,
  "SHA-512": 64,
};

export interface GenerateSecretOptions {
  /**
   * Secret length in bytes. Defaults to the block size of `algorithm`: 20 for
   * SHA-1, 32 for SHA-256, 64 for SHA-512.
   */
  size?: number;
  /** Algorithm the secret is sized for. @defaultValue "SHA-1" */
  algorithm?: AlgorithmInput;
}

export interface GeneratedSecret {
  /** The raw secret. */
  bytes: Uint8Array;
  /** Base32 form, for `otpauth://` URIs and manual entry. */
  base32: string;
  /** Hex form, for storage schemes that expect it. */
  hex: string;
}

/**
 * Generates a cryptographically random shared secret.
 *
 * @example
 * ```ts
 * const secret = generateSecret();
 * await db.users.update(id, { totpSecret: secret.base32 });
 * ```
 *
 * @throws {TOTPError} `INVALID_SECRET` if `size` is under 16 bytes, the floor
 * RFC 4226 sets for the shared secret.
 */
export function generateSecret(options: GenerateSecretOptions = {}): GeneratedSecret {
  const algorithm = normalizeAlgorithm(options.algorithm ?? "SHA-1");
  const size = options.size ?? RECOMMENDED_SIZE[algorithm];

  if (!Number.isInteger(size) || size < 16) {
    throw new TOTPError(
      "INVALID_SECRET",
      `size must be an integer of at least 16 bytes, received ${size}.`,
    );
  }

  const bytes = randomBytes(size);
  return { bytes, base32: base32Encode(bytes), hex: hexEncode(bytes) };
}
