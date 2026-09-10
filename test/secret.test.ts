import { describe, expect, it } from "vitest";
import { TOTPError, base32Decode, generateSecret, generateTOTP, hexDecode } from "../src/index.js";

describe("generateSecret", () => {
  it("defaults to the 20 bytes RFC 4226 recommends for SHA-1", () => {
    expect(generateSecret().bytes).toHaveLength(20);
  });

  it("sizes the secret to the block size of the chosen algorithm", () => {
    expect(generateSecret({ algorithm: "SHA-256" }).bytes).toHaveLength(32);
    expect(generateSecret({ algorithm: "SHA-512" }).bytes).toHaveLength(64);
  });

  it("honours an explicit size over the algorithm default", () => {
    expect(generateSecret({ algorithm: "SHA-512", size: 20 }).bytes).toHaveLength(20);
  });

  it("returns consistent base32 and hex encodings of the same bytes", () => {
    const secret = generateSecret();
    expect(base32Decode(secret.base32)).toEqual(secret.bytes);
    expect(hexDecode(secret.hex)).toEqual(secret.bytes);
  });

  it("produces a secret usable in either encoding", async () => {
    const secret = generateSecret();
    const fromBytes = await generateTOTP({ secret: secret.bytes, timestamp: 0 });
    const fromBase32 = await generateTOTP({ secret: secret.base32, timestamp: 0 });
    expect(fromBase32).toBe(fromBytes);
  });

  it("does not repeat itself", () => {
    const seen = new Set(Array.from({ length: 100 }, () => generateSecret().hex));
    expect(seen.size).toBe(100);
  });

  it("rejects sizes below the RFC 4226 floor of 16 bytes", () => {
    expect(() => generateSecret({ size: 15 })).toThrow(TOTPError);
    expect(() => generateSecret({ size: 20.5 })).toThrow(TOTPError);
    expect(() => generateSecret({ size: 16 })).not.toThrow();
  });

  it("rejects an unknown algorithm", () => {
    // @ts-expect-error exercising the runtime guard for untyped callers
    expect(() => generateSecret({ algorithm: "MD5" })).toThrow(/Unsupported algorithm/);
  });
});
