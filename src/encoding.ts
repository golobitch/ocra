import { TOTPError } from "./errors.js";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * Decodes an RFC 4648 base32 string into bytes.
 *
 * Input is case-insensitive and tolerates the separators authenticator apps
 * and QR codes routinely include: spaces, hyphens and `=` padding.
 *
 * @throws {TOTPError} `INVALID_SECRET` if the input contains a character
 * outside the base32 alphabet, or ends on a partial byte.
 */
export function base32Decode(input: string): Uint8Array {
  const normalized = input.replace(/[\s-]/g, "").replace(/=+$/, "").toUpperCase();
  if (normalized.length === 0) {
    throw new TOTPError("INVALID_SECRET", "Base32 secret is empty.");
  }

  const bytes = new Uint8Array(Math.floor((normalized.length * 5) / 8));
  let bitBuffer = 0;
  let bitCount = 0;
  let byteIndex = 0;

  for (let i = 0; i < normalized.length; i++) {
    const char = normalized[i] as string;
    const value = BASE32_ALPHABET.indexOf(char);
    if (value === -1) {
      throw new TOTPError(
        "INVALID_SECRET",
        `Invalid base32 character ${JSON.stringify(char)} at index ${i}.`,
      );
    }

    bitBuffer = (bitBuffer << 5) | value;
    bitCount += 5;

    if (bitCount >= 8) {
      bitCount -= 8;
      bytes[byteIndex++] = (bitBuffer >>> bitCount) & 0xff;
    }
  }

  // Whatever is left over must be zero padding, never significant bits.
  if (bitCount >= 5 || (bitBuffer & ((1 << bitCount) - 1)) !== 0) {
    throw new TOTPError("INVALID_SECRET", "Base32 secret ends on a partial byte.");
  }

  return bytes.subarray(0, byteIndex);
}

/** Encodes bytes as an unpadded RFC 4648 base32 string. */
export function base32Encode(bytes: Uint8Array): string {
  let output = "";
  let bitBuffer = 0;
  let bitCount = 0;

  for (const byte of bytes) {
    bitBuffer = (bitBuffer << 8) | byte;
    bitCount += 8;
    while (bitCount >= 5) {
      bitCount -= 5;
      output += BASE32_ALPHABET[(bitBuffer >>> bitCount) & 0x1f];
    }
  }

  if (bitCount > 0) {
    output += BASE32_ALPHABET[(bitBuffer << (5 - bitCount)) & 0x1f];
  }

  return output;
}

/**
 * Decodes a hex string into bytes.
 *
 * @throws {TOTPError} `INVALID_SECRET` if the input is not an even-length run
 * of hex digits.
 */
export function hexDecode(input: string): Uint8Array {
  const normalized = input.replace(/\s/g, "");
  if (normalized.length === 0 || normalized.length % 2 !== 0) {
    throw new TOTPError("INVALID_SECRET", "Hex secret must have an even, non-zero length.");
  }
  if (!/^[0-9a-fA-F]+$/.test(normalized)) {
    throw new TOTPError("INVALID_SECRET", "Hex secret contains a non-hex character.");
  }

  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Encodes bytes as a lowercase hex string. */
export function hexEncode(bytes: Uint8Array): string {
  let output = "";
  for (const byte of bytes) {
    output += byte.toString(16).padStart(2, "0");
  }
  return output;
}

/** Encodes a string as UTF-8 bytes. */
export function utf8Decode(input: string): Uint8Array {
  return new TextEncoder().encode(input);
}
