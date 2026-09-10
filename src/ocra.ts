import { digest, hmac, normalizeAlgorithm, timingSafeEqual } from "./crypto.js";
import { hexDecode, hexEncode, utf8Decode } from "./encoding.js";
import { TOTPError } from "./errors.js";
import { encodeCounter, normalizeSecret, truncate, validateWindow } from "./hotp.js";
import { DIGEST_BYTES, parseOCRASuite } from "./ocra-suite.js";
import type { ChallengeFormat, OCRASuite } from "./ocra-suite.js";
import type { AlgorithmInput, Secret } from "./types.js";

/** The Q field is always 128 bytes, zero-padded on the right (RFC 6287 §5.1). */
const QUESTION_BYTES = 128;

/**
 * A challenge question.
 *
 * An array is concatenated into a single challenge, which is what the mutual
 * and signature modes require: pass the other party's question first, then your
 * own (RFC 6287 §5.1). Each element is length-checked against the suite, and
 * the result is identical to passing the joined string.
 */
export type Challenge = string | readonly string[] | Uint8Array;

export interface OCRAOptions {
  /** The OCRASuite, as a string or already parsed by {@link parseOCRASuite}. */
  suite: string | OCRASuite;
  /** Shared secret: raw bytes, or a base32 string. */
  secret: Secret;
  /** The challenge question(s). Required — the Q field is mandatory in OCRA. */
  question: Challenge;
  /** Counter `C`. Required if, and only if, the suite includes `C`. */
  counter?: number | bigint;
  /**
   * The *hash* of the PIN/password, as raw bytes or a hex string, exactly the
   * digest length named by the suite's `PH`. {@link hashOCRAPassword} computes
   * it. Required if, and only if, the suite includes `P`.
   */
  passwordHash?: Uint8Array | string;
  /**
   * Session information `S`, as raw bytes or a UTF-8 string. Required if, and
   * only if, the suite includes `S`.
   */
  session?: Uint8Array | string;
  /**
   * Point in time for `T`, as a `Date` or Unix milliseconds. Used if, and only
   * if, the suite includes `T`. @defaultValue `Date.now()`
   */
  timestamp?: number | Date;
}

export interface VerifyOCRAOptions extends OCRAOptions {
  /** The response supplied by the other party. */
  response: string;
  /**
   * Counter values past `counter` to also accept, for resynchronization. Only
   * meaningful when the suite includes `C`. @defaultValue 0
   */
  counterWindow?: number;
  /**
   * Time steps of drift to accept on either side. Only meaningful when the
   * suite includes `T`. @defaultValue 1
   */
  timeWindow?: number;
}

/** Where a response matched, relative to the counter and time step asked for. */
export interface OCRADelta {
  /** Counter steps past the supplied counter. `0` unless the suite uses `C`. */
  counter: number;
  /** Time steps from the supplied timestamp. `0` unless the suite uses `T`. */
  time: number;
}

/**
 * Computes an OCRA response (RFC 6287).
 *
 * @example One-way challenge-response
 * ```ts
 * const response = await generateOCRA({
 *   suite: "OCRA-1:HOTP-SHA1-6:QN08",
 *   secret,
 *   question: "00000000",
 * });
 * ```
 *
 * @example Mutual challenge-response, as computed by the server
 * ```ts
 * await generateOCRA({
 *   suite: "OCRA-1:HOTP-SHA256-8:QA08",
 *   secret,
 *   question: [clientChallenge, serverChallenge],
 * });
 * ```
 *
 * @returns The truncated decimal response, or — when the suite's truncation
 * length is `0` — the full HMAC as a lowercase hex string.
 */
export async function generateOCRA(options: OCRAOptions): Promise<string> {
  const suite = resolveSuite(options.suite);
  const secret = normalizeSecret(options.secret);
  const dataInput = buildDataInput(suite, options);

  const mac = await hmac(suite.algorithm, secret, dataInput);
  // RFC 6287 §5.2: t = 0 means no truncation; the full HMAC is the response.
  return suite.digits === 0 ? hexEncode(mac) : truncate(mac, suite.digits);
}

/**
 * Verifies an OCRA response, returning where it matched, or `null`.
 *
 * Persist the returned offsets: a counter suite should advance past
 * `counter + delta.counter`, and a repeat of an accepted time step is a replay.
 */
export async function verifyOCRADelta(options: VerifyOCRAOptions): Promise<OCRADelta | null> {
  const { response, counterWindow = 0, timeWindow = 1, ...rest } = options;
  const suite = resolveSuite(rest.suite);

  // A window over a field the suite does not carry would just repeat the same
  // computation, so collapse it to a single attempt.
  const counterSteps = suite.counter ? validateWindow(counterWindow) : 0;
  const timeSteps = suite.timestamp ? validateWindow(timeWindow) : 0;

  const expectedLength = suite.digits === 0 ? DIGEST_BYTES[suite.algorithm] * 2 : suite.digits;
  if (typeof response !== "string" || response.length !== expectedLength) return null;

  const baseTimestamp = resolveTimestamp(rest.timestamp);

  for (const time of searchOrder(timeSteps)) {
    const shifted = baseTimestamp + time * (suite.timestamp?.seconds ?? 0) * 1000;
    if (shifted < 0) continue;

    for (let counter = 0; counter <= counterSteps; counter++) {
      const candidate = await generateOCRA({
        ...rest,
        suite,
        // Left undefined when the caller omitted it, so a counter suite reports
        // the missing parameter instead of quietly verifying against zero.
        ...(suite.counter &&
          rest.counter !== undefined && { counter: toCounter(rest.counter) + BigInt(counter) }),
        ...(suite.timestamp && { timestamp: shifted }),
      });
      if (timingSafeEqual(candidate, response)) return { counter, time };
    }
  }

  return null;
}

/**
 * Verifies an OCRA response.
 *
 * @example
 * ```ts
 * const ok = await verifyOCRA({
 *   suite: "OCRA-1:HOTP-SHA1-6:QN08",
 *   secret,
 *   question: challenge,
 *   response: submitted,
 * });
 * ```
 */
export async function verifyOCRA(options: VerifyOCRAOptions): Promise<boolean> {
  return (await verifyOCRADelta(options)) !== null;
}

/**
 * Hashes a PIN or password for the suite's `P` parameter.
 *
 * @example
 * ```ts
 * const passwordHash = await hashOCRAPassword("1234");
 * ```
 */
export async function hashOCRAPassword(
  password: string | Uint8Array,
  algorithm: AlgorithmInput = "SHA-1",
): Promise<Uint8Array> {
  const bytes = typeof password === "string" ? utf8Decode(password) : password;
  return digest(normalizeAlgorithm(algorithm), bytes);
}

/**
 * The number of time steps `T` that a suite's `T` parameter encodes.
 *
 * @throws {TOTPError} `INVALID_PARAMETER` if the suite has no `T` component.
 */
export function ocraTimeSteps(suite: string | OCRASuite, timestamp?: number | Date): bigint {
  const parsed = resolveSuite(suite);
  if (!parsed.timestamp) {
    throw new TOTPError("INVALID_PARAMETER", `Suite ${JSON.stringify(parsed.value)} has no T component.`);
  }
  return BigInt(Math.floor(resolveTimestamp(timestamp) / 1000 / parsed.timestamp.seconds));
}

/** Assembles `DataInput = {OCRASuite | 00 | C | Q | P | S | T}` (RFC 6287 §5.1). */
function buildDataInput(suite: OCRASuite, options: OCRAOptions): Uint8Array {
  const suiteBytes = utf8Decode(suite.value);
  const chunks: Uint8Array[] = [suiteBytes, new Uint8Array(1)];

  if (suite.counter) {
    chunks.push(encodeCounter(toCounter(required(options.counter, "counter", suite))));
  } else {
    rejectUnused(options.counter, "counter", "C", suite);
  }

  chunks.push(encodeQuestion(suite, options.question));

  if (suite.password) {
    chunks.push(encodePassword(suite, required(options.passwordHash, "passwordHash", suite)));
  } else {
    rejectUnused(options.passwordHash, "passwordHash", "P", suite);
  }

  if (suite.session) {
    chunks.push(encodeSession(suite, required(options.session, "session", suite)));
  } else {
    rejectUnused(options.session, "session", "S", suite);
  }

  if (suite.timestamp) {
    chunks.push(encodeCounter(ocraTimeSteps(suite, options.timestamp)));
  }

  return concat(chunks);
}

/**
 * Encodes the challenge into the fixed 128-byte Q field.
 *
 * Each format is first rendered as hex, then right-padded with `0` nibbles, so
 * a value whose hex form has an odd length keeps the reference implementation's
 * trailing-nibble behaviour.
 */
function encodeQuestion(suite: OCRASuite, question: Challenge): Uint8Array {
  const hex = questionHex(suite, question);
  if (hex.length > QUESTION_BYTES * 2) {
    throw new TOTPError(
      "INVALID_CHALLENGE",
      `Challenge encodes to more than ${QUESTION_BYTES} bytes.`,
    );
  }
  return hexDecode(hex.padEnd(QUESTION_BYTES * 2, "0"));
}

function questionHex(suite: OCRASuite, question: Challenge): string {
  if (question instanceof Uint8Array) {
    if (question.length === 0) throw challengeError("Challenge must not be empty.");
    return hexEncode(question);
  }

  const parts = typeof question === "string" ? [question] : question;
  if (!Array.isArray(parts) || parts.length === 0) {
    throw challengeError("question must be a string, a non-empty array of strings, or bytes.");
  }

  for (const part of parts) {
    if (typeof part !== "string" || part.length === 0) {
      throw challengeError("Each challenge must be a non-empty string.");
    }
    // Only meaningful per part; the concatenation in mutual mode is expected to
    // exceed the suite's per-party maximum.
    if (parts.length > 1 && part.length > suite.challenge.length) {
      throw challengeError(
        `Challenge ${JSON.stringify(part)} exceeds the ${suite.challenge.length} characters allowed by ${JSON.stringify(suite.value)}.`,
      );
    }
  }

  return encodeByFormat(suite.challenge.format, parts.join(""));
}

function encodeByFormat(format: ChallengeFormat, value: string): string {
  switch (format) {
    case "N":
      if (!/^\d+$/.test(value)) {
        throw challengeError(`Numeric challenge must be decimal digits, received ${JSON.stringify(value)}.`);
      }
      // Read as a decimal number and re-render in hex, per RFC 6287 Appendix B.
      return BigInt(value).toString(16);
    case "H":
      if (!/^[0-9a-fA-F]+$/.test(value)) {
        throw challengeError(`Hexadecimal challenge must be hex digits, received ${JSON.stringify(value)}.`);
      }
      return value;
    case "A":
      return hexEncode(utf8Decode(value));
  }
}

function encodePassword(suite: OCRASuite, passwordHash: Uint8Array | string): Uint8Array {
  const bytes = typeof passwordHash === "string" ? hexDecode(passwordHash) : passwordHash;
  const expected = suite.password?.bytes as number;

  if (!(bytes instanceof Uint8Array)) {
    throw new TOTPError("INVALID_PASSWORD", "passwordHash must be a Uint8Array or a hex string.");
  }
  // A short value here means a wrong hash, not something to pad around.
  if (bytes.length !== expected) {
    throw new TOTPError(
      "INVALID_PASSWORD",
      `passwordHash must be the ${expected}-byte ${suite.password?.algorithm} digest, received ${bytes.length} bytes.`,
    );
  }
  return bytes;
}

/**
 * Encodes session information into its fixed-length field.
 *
 * Shorter values are padded on the **left**, matching the reference
 * implementation in RFC 6287 Appendix A. Pass exactly `bytes` bytes if you need
 * to be certain of the layout — implementations disagree on this point.
 */
function encodeSession(suite: OCRASuite, session: Uint8Array | string): Uint8Array {
  const bytes = typeof session === "string" ? utf8Decode(session) : session;
  const size = suite.session?.bytes as number;

  if (!(bytes instanceof Uint8Array)) {
    throw new TOTPError("INVALID_SESSION", "session must be a Uint8Array or a string.");
  }
  if (bytes.length > size) {
    throw new TOTPError(
      "INVALID_SESSION",
      `session must be at most ${size} bytes for ${JSON.stringify(suite.value)}, received ${bytes.length}.`,
    );
  }

  const field = new Uint8Array(size);
  field.set(bytes, size - bytes.length);
  return field;
}

function resolveSuite(suite: string | OCRASuite): OCRASuite {
  return typeof suite === "string" ? parseOCRASuite(suite) : suite;
}

function resolveTimestamp(timestamp: number | Date | undefined): number {
  if (timestamp === undefined) return Date.now();
  const value = timestamp instanceof Date ? timestamp.getTime() : timestamp;
  if (!Number.isFinite(value)) {
    throw new TOTPError("INVALID_PARAMETER", `timestamp must be a finite number or Date, received ${timestamp}.`);
  }
  return value;
}

function toCounter(counter: number | bigint): bigint {
  if (typeof counter === "number" && !Number.isSafeInteger(counter)) {
    throw new TOTPError("INVALID_COUNTER", `counter must be a safe integer or a bigint, received ${counter}.`);
  }
  return BigInt(counter);
}

/** `0, -1, +1, -2, +2, …` up to `±window`. */
function searchOrder(window: number): number[] {
  const order = [0];
  for (let i = 1; i <= window; i++) order.push(-i, i);
  return order;
}

function required<T>(value: T | undefined, name: string, suite: OCRASuite): T {
  if (value === undefined || value === null) {
    throw new TOTPError(
      "INVALID_PARAMETER",
      `Suite ${JSON.stringify(suite.value)} requires ${name}.`,
    );
  }
  return value;
}

/** Rejects an input the suite has no field for, rather than ignoring it. */
function rejectUnused(value: unknown, name: string, component: string, suite: OCRASuite): void {
  if (value !== undefined && value !== null) {
    throw new TOTPError(
      "INVALID_PARAMETER",
      `Suite ${JSON.stringify(suite.value)} has no ${component} component, so ${name} would be ignored.`,
    );
  }
}

function challengeError(message: string): TOTPError {
  return new TOTPError("INVALID_CHALLENGE", message);
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}
