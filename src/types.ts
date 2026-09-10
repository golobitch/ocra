/**
 * Hash algorithm backing the HMAC, as named by RFC 4226 / RFC 6238 and the
 * `otpauth://` URI format.
 *
 * SHA-1 is the default because it is what virtually every authenticator app
 * implements. Its use inside HMAC is not affected by the collision attacks on
 * bare SHA-1, so this remains a safe default.
 */
export type Algorithm = "SHA-1" | "SHA-256" | "SHA-512";

/** Aliases accepted anywhere an {@link Algorithm} is expected. */
export type AlgorithmInput = Algorithm | "SHA1" | "SHA256" | "SHA512" | Lowercase<Algorithm>;

/**
 * A shared secret, given either as raw bytes or as a base32 string of the kind
 * authenticator apps display.
 */
export type Secret = Uint8Array | string;
