# @golobic/ocra

Zero-dependency OATH one-time passwords for TypeScript:

- **TOTP** — time-based, [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)
- **HOTP** — counter-based, [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226)
- **OCRA** — challenge-response and signature, [RFC 6287](https://datatracker.ietf.org/doc/html/rfc6287)

Plus:

- **Zero dependencies.** Built on WebCrypto — nothing to audit but this package.
- **Runs everywhere.** Node 20+, Deno, Bun, browsers, Cloudflare Workers and other edge runtimes.
- **Verified against the RFCs.** Every test vector in RFC 4226 Appendix D, RFC 6238 Appendix B and RFC 6287 Appendix C is in the test suite.
- **Fully typed**, ESM + CJS, tree-shakeable — importing only TOTP costs about 1.7 KB gzipped.

## Install

```sh
pnpm add @golobic/ocra
```

```sh
npm install @golobic/ocra
```

## Quick start

```ts
import { generateSecret, createOTPAuthURI, verifyTOTP } from "@golobic/ocra";

// 1. Enrolment: create a secret and store it against the user.
const secret = generateSecret();
await db.users.update(userId, { totpSecret: secret.base32 });

// 2. Show the user a QR code encoding this URI.
const uri = createOTPAuthURI({
  secret: secret.base32,
  account: "alice@example.com",
  issuer: "ACME Co",
});

// 3. Login: check the code they type in.
if (await verifyTOTP({ secret: secret.base32, token: submittedCode })) {
  // accepted
}
```

Every function that hashes is `async`, because WebCrypto is. That is what lets the
same code run on the server and in the browser.

## API

### `generateTOTP(options): Promise<string>`

| Option      | Type                              | Default     | Meaning                                          |
| ----------- | --------------------------------- | ----------- | ------------------------------------------------ |
| `secret`    | `Uint8Array \| string`            | *required*  | Raw bytes, or a base32 string                    |
| `digits`    | `number`                          | `6`         | Code length                                      |
| `period`    | `number`                          | `30`        | Time step in seconds (RFC 6238 `X`)              |
| `algorithm` | `"SHA-1" \| "SHA-256" \| "SHA-512"` | `"SHA-1"` | HMAC hash                                        |
| `timestamp` | `number \| Date`                  | `Date.now()`| Point in time, as Unix **milliseconds**          |
| `epoch`     | `number`                          | `0`         | Start of the counting epoch (RFC 6238 `T0`), ms  |

```ts
const code = await generateTOTP({ secret: "JBSWY3DPEHPK3PXP" });
```

Secrets given as strings are decoded as base32, case-insensitively, tolerating the
spaces, hyphens and `=` padding that authenticator apps and QR codes include.

### `verifyTOTP(options): Promise<boolean>`

Takes everything `generateTOTP` does, plus:

| Option   | Type     | Default    | Meaning                                     |
| -------- | -------- | ---------- | ------------------------------------------- |
| `token`  | `string` | *required* | The code the user submitted                 |
| `window` | `number` | `1`        | Time steps of drift to accept on either side |

```ts
const ok = await verifyTOTP({ secret, token: "492039" });
```

The default window accepts a code up to 30 seconds old or 30 seconds early, which
covers ordinary clock drift and the time a user spends typing. Widen it only if you
have to; each extra step is another code an attacker gets to guess.

Codes are compared in constant time.

### `verifyTOTPDelta(options): Promise<number | null>`

Same inputs, but returns *where* the code matched: `0` for the current time step,
`-1` for the previous one, `+1` for the next, and `null` for no match.

Use it to stop replays — a code is valid for its whole time step, so without this
an attacker who observes a code can reuse it:

```ts
const delta = await verifyTOTPDelta({ secret: user.totpSecret, token });
if (delta === null) throw new Error("Invalid code");

const step = totpCounter({}) + BigInt(delta);
if (user.lastTotpStep !== null && step <= user.lastTotpStep) {
  throw new Error("Code already used");
}
await db.users.update(user.id, { lastTotpStep: step });
```

A user whose `delta` is consistently non-zero has a drifting device clock.

### `generateSecret(options?): GeneratedSecret`

```ts
const { bytes, base32, hex } = generateSecret();
```

Draws from the platform CSPRNG. Defaults to the block size of the algorithm — 20
bytes for SHA-1, 32 for SHA-256, 64 for SHA-512 — and refuses anything under the
16 bytes RFC 4226 requires.

### `createOTPAuthURI(options)` / `parseOTPAuthURI(uri)`

The [Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
that authenticator apps read from a QR code. This package does not draw QR codes;
pass the URI to a QR library of your choice.

```ts
createOTPAuthURI({ secret, account: "alice@example.com", issuer: "ACME Co" });
// otpauth://totp/ACME%20Co:alice%40example.com?secret=…&issuer=ACME+Co&algorithm=SHA1&digits=6&period=30

parseOTPAuthURI(uri);
// { secret: "…", account: "alice@example.com", issuer: "ACME Co",
//   digits: 6, period: 30, algorithm: "SHA-1" }
```

### `timeRemaining(options?): number`

Milliseconds until the current code expires, for a countdown ring:

```ts
const ms = timeRemaining(); // 0 < ms <= 30_000
```

### `totpCounter(options?): bigint`

The time-step counter `T` that `generateTOTP` would use. Useful for replay
protection, as above.

### HOTP

The counter-based RFC 4226 mode, for hardware tokens and scratch-code schemes:

```ts
import { generateHOTP, verifyHOTPDelta } from "@golobic/ocra";

const code = await generateHOTP({ secret, counter: 0 });

// `window` only looks forward, to resynchronize after codes the user generated
// but never submitted.
const delta = await verifyHOTPDelta({ secret, counter: stored, token, window: 10 });
if (delta !== null) await saveNextCounter(stored + BigInt(delta) + 1n);
```

Counters accept a `number` or a `bigint`, up to the full unsigned 64-bit range.

## OCRA (RFC 6287)

OCRA generalizes HOTP: instead of a bare counter, the HMAC covers a structured
**DataInput** built from a challenge, and optionally a counter, a PIN hash,
session data and a timestamp. Which of those are present is declared by an
**OCRASuite** string such as `OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1`.

```ts
import { generateOCRA, verifyOCRA } from "@golobic/ocra";

// The server sends a challenge; the token computes a response.
const response = await generateOCRA({
  suite: "OCRA-1:HOTP-SHA1-6:QN08",
  secret,
  question: "00000000",
});

const ok = await verifyOCRA({
  suite: "OCRA-1:HOTP-SHA1-6:QN08",
  secret,
  question: "00000000",
  response: submitted,
});
```

### Options

| Option         | Required when                  | Meaning                                                   |
| -------------- | ------------------------------ | --------------------------------------------------------- |
| `suite`        | always                         | OCRASuite string, or the result of `parseOCRASuite`        |
| `secret`       | always                         | Shared secret: bytes or base32                             |
| `question`     | always                         | Challenge — `Q` is mandatory in every OCRA mode            |
| `counter`      | the suite has `C`              | Moving factor, `number` or `bigint`                        |
| `passwordHash` | the suite has `P`              | The **digest** of the PIN, from `hashOCRAPassword`         |
| `session`      | the suite has `S`              | Session data, bytes or a UTF-8 string                      |
| `timestamp`    | the suite has `T`              | `Date` or Unix ms; defaults to now                         |

Passing a parameter the suite has no field for is an error rather than being
silently ignored — a `passwordHash` that never reaches the HMAC would otherwise
look like it was protecting something.

### Mutual challenge-response

Both parties compute over the concatenation of the two challenges, so pass them
as an array — the other party's question first, then your own:

```ts
// Server verifies the client's response.
await verifyOCRA({
  suite: "OCRA-1:HOTP-SHA256-8:QA08",
  secret,
  question: [clientChallenge, serverChallenge],
  response: fromClient,
});
```

An array is exactly equivalent to passing the joined string, except that each
element is length-checked against the suite individually.

### PIN / password

`P` carries a *hash* of the PIN, never the PIN itself:

```ts
import { hashOCRAPassword } from "@golobic/ocra";

const passwordHash = await hashOCRAPassword("1234");            // SHA-1 by default
const sha256Hash = await hashOCRAPassword("1234", "SHA-256");   // for a PSHA256 suite
```

The digest must be exactly the length the suite's `PH` names; a mismatch throws
`INVALID_PASSWORD` rather than being padded into place.

### Inspecting a suite

```ts
import { parseOCRASuite } from "@golobic/ocra";

parseOCRASuite("OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1");
// { value: "OCRA-1:…", version: 1, algorithm: "SHA-256", digits: 8,
//   counter: true, challenge: { format: "N", length: 8 },
//   password: { algorithm: "SHA-1", bytes: 20 } }
```

Parsing is case-insensitive, but `value` keeps the string verbatim — the suite is
hashed as part of DataInput, so changing its case changes every response.

`verifyOCRADelta` returns `{ counter, time }` offsets for the same replay and
drift handling as TOTP, with `counterWindow` (forward only, default `0`) and
`timeWindow` (either direction, default `1`).

### Two things to know

- **A truncation length of `0`** means no truncation, per RFC 6287 §5.2. Those
  suites return the full HMAC as a lowercase hex string, not decimal digits.
  (The RFC's own reference implementation returns `"0"` here; it is wrong.)
- **Session data is right-aligned** in its fixed-length field — short values are
  padded on the *left*, matching the reference implementation in RFC 6287
  Appendix A. The RFC has no test vectors covering `S`, and implementations
  disagree. Pass exactly `nnn` bytes if you need certainty.

### Encoding helpers

`base32Encode`, `base32Decode`, `hexEncode`, `hexDecode` and `utf8Decode`, exported
because secrets arrive in all of these forms:

```ts
import { hexDecode, generateTOTP } from "@golobic/ocra";

await generateTOTP({ secret: hexDecode("3132333435363738393031323334353637383930") });
```

### Errors

Every failure is a `TOTPError` with a stable `code`: `INVALID_SECRET`,
`INVALID_DIGITS`, `INVALID_PERIOD`, `INVALID_COUNTER`, `INVALID_WINDOW`,
`INVALID_ALGORITHM`, `INVALID_URI`, `INVALID_SUITE`, `INVALID_CHALLENGE`,
`INVALID_PASSWORD`, `INVALID_SESSION`, `INVALID_PARAMETER` or
`CRYPTO_UNAVAILABLE`. Match on `code`, not on the message.

A **wrong code is not an error** — `verifyTOTP` and `verifyOCRA` return `false`. `TOTPError` means
the call itself was misconfigured, so a bad secret or a bad `digits` can never be
mistaken for a failed login.

## Notes on use

- **SHA-1 is the right default.** Practically every authenticator app implements only
  SHA-1; the collision attacks on bare SHA-1 do not apply to its use inside HMAC.
- **Store secrets encrypted.** A TOTP secret is a password equivalent: anyone holding
  it can generate valid codes forever.
- **Rate-limit verification.** A 6-digit code is one in a million, and a window of 1
  puts three of them in play at once. Lock the account after a handful of failures.
- **Consume each code once**, using `verifyTOTPDelta` as shown above.

## Compatibility

Requires a WebCrypto implementation on `globalThis.crypto` — Node 20+, Deno, Bun,
all current browsers, and edge runtimes such as Cloudflare Workers.

Node 18 is past end-of-life and does not expose WebCrypto as a global, only as
`webcrypto` on `node:crypto`. If you are stuck on it, install the global yourself
before calling into this package (not covered by CI):

```js
import { webcrypto } from "node:crypto";
globalThis.crypto = webcrypto;
```

## Development

```sh
pnpm install
pnpm test          # vitest, including every RFC test vector
pnpm coverage
pnpm typecheck
pnpm build
```

## License

Apache-2.0
