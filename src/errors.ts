/**
 * Error codes attached to every {@link TOTPError}. Use these instead of
 * matching on the message, which is not part of the public contract.
 */
export type TOTPErrorCode =
  | "INVALID_SECRET"
  | "INVALID_DIGITS"
  | "INVALID_PERIOD"
  | "INVALID_COUNTER"
  | "INVALID_WINDOW"
  | "INVALID_ALGORITHM"
  | "INVALID_URI"
  | "INVALID_SUITE"
  | "INVALID_CHALLENGE"
  | "INVALID_PASSWORD"
  | "INVALID_SESSION"
  | "INVALID_PARAMETER"
  | "CRYPTO_UNAVAILABLE";

/** Every error thrown by this package is a `TOTPError`. */
export class TOTPError extends Error {
  readonly code: TOTPErrorCode;

  constructor(code: TOTPErrorCode, message: string) {
    super(message);
    this.name = "TOTPError";
    this.code = code;
    // Restores the prototype chain when the package is down-compiled to ES5.
    Object.setPrototypeOf(this, TOTPError.prototype);
  }
}
