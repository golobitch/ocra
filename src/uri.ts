import { normalizeAlgorithm } from "./crypto.js";
import { base32Encode } from "./encoding.js";
import { TOTPError } from "./errors.js";
import { normalizeSecret, validateDigits } from "./hotp.js";
import type { Algorithm, AlgorithmInput, Secret } from "./types.js";

export interface OTPAuthURIOptions {
  /** Shared secret: raw bytes, or a base32 string. */
  secret: Secret;
  /** Identifies the account, e.g. an email address. Shown by the app. */
  account: string;
  /** Identifies the service, e.g. `"ACME Co"`. Shown by the app. */
  issuer?: string;
  /** @defaultValue 6 */
  digits?: number;
  /** @defaultValue 30 */
  period?: number;
  /** @defaultValue "SHA-1" */
  algorithm?: AlgorithmInput;
}

export interface ParsedOTPAuthURI {
  /** Base32 secret, as it appeared in the URI. */
  secret: string;
  account: string;
  issuer?: string;
  digits: number;
  period: number;
  algorithm: Algorithm;
}

/**
 * Builds the `otpauth://totp/...` URI that authenticator apps read from a QR
 * code, per the Key Uri Format.
 *
 * @example
 * ```ts
 * createOTPAuthURI({ secret, account: "alice@example.com", issuer: "ACME Co" });
 * // otpauth://totp/ACME%20Co:alice%40example.com?secret=...&issuer=ACME%20Co&...
 * ```
 *
 * @see https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 */
export function createOTPAuthURI(options: OTPAuthURIOptions): string {
  const { account, issuer } = options;
  if (typeof account !== "string" || account.length === 0) {
    throw new TOTPError("INVALID_URI", "account must be a non-empty string.");
  }
  if (issuer !== undefined && issuer.includes(":")) {
    throw new TOTPError("INVALID_URI", "issuer must not contain a colon.");
  }

  const secretBytes = normalizeSecret(options.secret);
  const base32 = typeof options.secret === "string" ? options.secret : base32Encode(secretBytes);
  const digits = validateDigits(options.digits ?? 6);
  const period = options.period ?? 30;
  const algorithm = normalizeAlgorithm(options.algorithm ?? "SHA-1");

  const label = issuer ? `${encode(issuer)}:${encode(account)}` : encode(account);

  const params = new URLSearchParams({ secret: base32.replace(/[\s-]/g, "").toUpperCase() });
  // Duplicated in the label above; apps that only read one of the two still
  // attribute the account correctly.
  if (issuer) params.set("issuer", issuer);
  params.set("algorithm", algorithm.replace("-", ""));
  params.set("digits", String(digits));
  params.set("period", String(period));

  return `otpauth://totp/${label}?${params.toString()}`;
}

/**
 * Parses an `otpauth://totp/...` URI back into its parameters, applying the
 * spec's defaults for anything the URI leaves out.
 *
 * @throws {TOTPError} `INVALID_URI` if the URI is malformed, is not a `totp`
 * URI, or carries no secret.
 */
export function parseOTPAuthURI(uri: string): ParsedOTPAuthURI {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    throw new TOTPError("INVALID_URI", `Not a valid URI: ${JSON.stringify(uri)}.`);
  }

  if (url.protocol !== "otpauth:") {
    throw new TOTPError("INVALID_URI", `Expected an otpauth: URI, received ${url.protocol}`);
  }
  if (url.host.toLowerCase() !== "totp") {
    throw new TOTPError("INVALID_URI", `Expected a totp URI, received type ${JSON.stringify(url.host)}.`);
  }

  const secret = url.searchParams.get("secret");
  if (!secret) {
    throw new TOTPError("INVALID_URI", "otpauth URI is missing the required secret parameter.");
  }

  const label = decode(url.pathname.replace(/^\//, ""));
  const separator = label.indexOf(":");
  const labelIssuer = separator === -1 ? undefined : label.slice(0, separator);
  const account = separator === -1 ? label : label.slice(separator + 1).replace(/^\s+/, "");

  // The issuer parameter wins over the label prefix, per the Key Uri Format.
  const issuer = url.searchParams.get("issuer") ?? labelIssuer;

  return {
    secret,
    account,
    ...(issuer ? { issuer } : {}),
    digits: validateDigits(parseIntParam(url.searchParams.get("digits"), 6, "digits")),
    period: parseIntParam(url.searchParams.get("period"), 30, "period"),
    algorithm: normalizeAlgorithm(url.searchParams.get("algorithm") ?? "SHA-1"),
  };
}

function parseIntParam(value: string | null, fallback: number, name: string): number {
  if (value === null || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new TOTPError("INVALID_URI", `${name} must be a positive integer, received ${JSON.stringify(value)}.`);
  }
  return parsed;
}

/** `encodeURIComponent`, with the sub-delims apps trip over also escaped. */
function encode(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

function decode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new TOTPError("INVALID_URI", "otpauth URI label is not valid percent-encoding.");
  }
}
