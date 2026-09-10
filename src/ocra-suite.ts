import { normalizeAlgorithm } from "./crypto.js";
import { TOTPError } from "./errors.js";
import type { Algorithm } from "./types.js";

/** Challenge question format: alphanumeric, numeric or hexadecimal. */
export type ChallengeFormat = "A" | "N" | "H";

/** Unit of the OCRA time step (RFC 6287 §6.3, Table 3). */
export type TimeStepUnit = "S" | "M" | "H";

/** Digest sizes, in bytes, of the hashes OCRA may use. */
export const DIGEST_BYTES: Record<Algorithm, number> = {
  "SHA-1": 20,
  "SHA-256": 32,
  "SHA-512": 64,
};

const UNIT_SECONDS: Record<TimeStepUnit, number> = { S: 1, M: 60, H: 3600 };

/** An OCRASuite string parsed into its components (RFC 6287 §6). */
export interface OCRASuite {
  /** The suite string exactly as given. These bytes are hashed, so they matter. */
  readonly value: string;
  /** OCRA version. Only version 1 is defined. */
  readonly version: number;
  /** Hash backing the HMAC. */
  readonly algorithm: Algorithm;
  /** Truncation length, or `0` for the untruncated HMAC (RFC 6287 §5.2). */
  readonly digits: number;
  /** Whether the DataInput carries the counter `C`. */
  readonly counter: boolean;
  /** The mandatory challenge `QFxx`, with the per-party maximum length. */
  readonly challenge: { readonly format: ChallengeFormat; readonly length: number };
  /** The optional PIN/password hash `PH`. */
  readonly password?: { readonly algorithm: Algorithm; readonly bytes: number };
  /** The optional session field `Snnn`. */
  readonly session?: { readonly bytes: number };
  /** The optional timestamp `TG`. */
  readonly timestamp?: {
    readonly unit: TimeStepUnit;
    readonly count: number;
    /** The time step in seconds, i.e. `count` scaled by `unit`. */
    readonly seconds: number;
  };
}

/**
 * Parses an OCRASuite string such as `OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1`.
 *
 * Parsing is case-insensitive, but {@link OCRASuite.value} preserves the string
 * verbatim — the suite is hashed as part of the DataInput, so changing its case
 * changes the resulting OCRA value.
 *
 * @throws {TOTPError} `INVALID_SUITE` for anything that is not a well-formed
 * suite this package can compute.
 */
export function parseOCRASuite(suite: string): OCRASuite {
  if (typeof suite !== "string" || suite.length === 0) {
    throw invalid("OCRASuite must be a non-empty string.");
  }

  const parts = suite.split(":");
  if (parts.length !== 3) {
    throw invalid(
      `Expected <Algorithm>:<CryptoFunction>:<DataInput>, received ${JSON.stringify(suite)}.`,
    );
  }
  const [algorithmPart, cryptoPart, dataPart] = parts as [string, string, string];

  const version = parseVersion(algorithmPart);
  const { algorithm, digits } = parseCryptoFunction(cryptoPart);
  const dataInput = parseDataInput(dataPart);

  return { value: suite, version, algorithm, digits, ...dataInput };
}

function parseVersion(part: string): number {
  const match = /^OCRA-(\d+)$/i.exec(part);
  if (!match) {
    throw invalid(`Expected an OCRA-v algorithm component, received ${JSON.stringify(part)}.`);
  }
  const version = Number(match[1]);
  if (version !== 1) {
    throw invalid(`Unsupported OCRA version ${version}. Only version 1 is defined.`);
  }
  return version;
}

function parseCryptoFunction(part: string): { algorithm: Algorithm; digits: number } {
  const match = /^HOTP-(SHA1|SHA256|SHA512)-(\d{1,2})$/i.exec(part);
  if (!match) {
    throw invalid(
      `Expected a HOTP-<hash>-<digits> CryptoFunction, received ${JSON.stringify(part)}.`,
    );
  }

  const digits = Number(match[2]);
  // RFC 6287 §5.2: t is a truncation length of 4-10 digits, or 0 for none.
  if (digits !== 0 && (digits < 4 || digits > 10)) {
    throw invalid(`CryptoFunction truncation must be 0 or 4-10 digits, received ${digits}.`);
  }

  return { algorithm: normalizeAlgorithm(match[1] as string), digits };
}

/** DataInput is `[C] | QFxx | [PH | Snnn | TG]`, in that order. */
function parseDataInput(part: string): Omit<OCRASuite, "value" | "version" | "algorithm" | "digits"> {
  const tokens = part.split("-");
  let index = 0;

  const counter = tokens[index]?.toUpperCase() === "C";
  if (counter) index++;

  const challenge = parseChallenge(tokens[index]);
  index++;

  let password: OCRASuite["password"];
  if (startsWith(tokens[index], "P")) {
    password = parsePassword(tokens[index] as string);
    index++;
  }

  let session: OCRASuite["session"];
  if (startsWith(tokens[index], "S")) {
    session = parseSession(tokens[index] as string);
    index++;
  }

  let timestamp: OCRASuite["timestamp"];
  if (startsWith(tokens[index], "T")) {
    timestamp = parseTimestamp(tokens[index] as string);
    index++;
  }

  if (index !== tokens.length) {
    throw invalid(
      `Unexpected DataInput component ${JSON.stringify(tokens[index])}. ` +
        "Expected [C]-QFxx-[PH]-[Snnn]-[TG], in that order.",
    );
  }

  return { counter, challenge, ...(password && { password }), ...(session && { session }), ...(timestamp && { timestamp }) };
}

function parseChallenge(token: string | undefined): OCRASuite["challenge"] {
  const match = /^Q([ANH])(\d{1,2})$/i.exec(token ?? "");
  if (!match) {
    throw invalid(
      `Expected a mandatory challenge component QFxx, received ${JSON.stringify(token ?? "")}.`,
    );
  }

  const length = Number(match[2]);
  if (length < 4 || length > 64) {
    throw invalid(`Challenge length must be 4-64, received ${length}.`);
  }

  return { format: (match[1] as string).toUpperCase() as ChallengeFormat, length };
}

function parsePassword(token: string): NonNullable<OCRASuite["password"]> {
  const match = /^P(SHA1|SHA256|SHA512)$/i.exec(token);
  if (!match) {
    throw invalid(`Expected a password component PSHA1/PSHA256/PSHA512, received ${JSON.stringify(token)}.`);
  }
  const algorithm = normalizeAlgorithm(match[1] as string);
  return { algorithm, bytes: DIGEST_BYTES[algorithm] };
}

function parseSession(token: string): NonNullable<OCRASuite["session"]> {
  // A bare "S" takes the default length of 64 bytes (RFC 6287 §6.3).
  if (token.toUpperCase() === "S") return { bytes: 64 };

  const match = /^S(\d{3})$/i.exec(token);
  if (!match) {
    throw invalid(`Expected a session component Snnn, received ${JSON.stringify(token)}.`);
  }
  const bytes = Number(match[1]);
  if (bytes < 1 || bytes > 512) {
    throw invalid(`Session length must be 001-512 bytes, received ${JSON.stringify(token)}.`);
  }
  return { bytes };
}

function parseTimestamp(token: string): NonNullable<OCRASuite["timestamp"]> {
  // A bare "T" takes the default step of one minute (RFC 6287 §6.3).
  if (token.toUpperCase() === "T") return { unit: "M", count: 1, seconds: 60 };

  const match = /^T(\d{1,2})([SMH])$/i.exec(token);
  if (!match) {
    throw invalid(`Expected a timestamp component TG, received ${JSON.stringify(token)}.`);
  }

  const count = Number(match[1]);
  const unit = (match[2] as string).toUpperCase() as TimeStepUnit;
  const max = unit === "H" ? 48 : 59;
  // Table 3 allows 0H, but a zero-length time step has no meaning here.
  if (count < 1 || count > max) {
    throw invalid(`Time step must be 1-${max} for unit ${unit}, received ${JSON.stringify(token)}.`);
  }

  return { unit, count, seconds: count * UNIT_SECONDS[unit] };
}

function startsWith(token: string | undefined, letter: string): boolean {
  return token !== undefined && token.slice(0, 1).toUpperCase() === letter;
}

function invalid(message: string): TOTPError {
  return new TOTPError("INVALID_SUITE", message);
}
