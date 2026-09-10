/**
 * Zero-dependency TOTP (RFC 6238), HOTP (RFC 4226) and OCRA (RFC 6287), built
 * on WebCrypto.
 *
 * @example Enrolling a user
 * ```ts
 * import { generateSecret, createOTPAuthURI } from "@golobic/ocra";
 *
 * const secret = generateSecret();
 * const uri = createOTPAuthURI({
 *   secret: secret.base32,
 *   account: "alice@example.com",
 *   issuer: "ACME Co",
 * });
 * ```
 *
 * @example Verifying a submitted code
 * ```ts
 * import { verifyTOTP } from "@golobic/ocra";
 *
 * const ok = await verifyTOTP({ secret: storedBase32, token: submitted });
 * ```
 *
 * @packageDocumentation
 */

export { TOTPError } from "./errors.js";
export type { TOTPErrorCode } from "./errors.js";

export type { Algorithm, AlgorithmInput, Secret } from "./types.js";

export { base32Decode, base32Encode, hexDecode, hexEncode, utf8Decode } from "./encoding.js";

export { generateHOTP, verifyHOTP, verifyHOTPDelta } from "./hotp.js";
export type { HOTPOptions, VerifyHOTPOptions } from "./hotp.js";

export { generateTOTP, verifyTOTP, verifyTOTPDelta, totpCounter, timeRemaining } from "./totp.js";
export type { TOTPOptions, VerifyTOTPOptions } from "./totp.js";

export { generateSecret } from "./secret.js";
export type { GenerateSecretOptions, GeneratedSecret } from "./secret.js";

export { createOTPAuthURI, parseOTPAuthURI } from "./uri.js";
export type { OTPAuthURIOptions, ParsedOTPAuthURI } from "./uri.js";

export { generateOCRA, verifyOCRA, verifyOCRADelta, hashOCRAPassword, ocraTimeSteps } from "./ocra.js";
export type { Challenge, OCRAOptions, VerifyOCRAOptions, OCRADelta } from "./ocra.js";

export { parseOCRASuite } from "./ocra-suite.js";
export type { OCRASuite, ChallengeFormat, TimeStepUnit } from "./ocra-suite.js";
