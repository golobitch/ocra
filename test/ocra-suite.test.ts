import { describe, expect, it } from "vitest";
import { TOTPError, parseOCRASuite } from "../src/index.js";

describe("parseOCRASuite", () => {
  it("parses the RFC 6287 §6.4 examples", () => {
    expect(parseOCRASuite("OCRA-1:HOTP-SHA512-8:C-QN08-PSHA1")).toEqual({
      value: "OCRA-1:HOTP-SHA512-8:C-QN08-PSHA1",
      version: 1,
      algorithm: "SHA-512",
      digits: 8,
      counter: true,
      challenge: { format: "N", length: 8 },
      password: { algorithm: "SHA-1", bytes: 20 },
    });

    expect(parseOCRASuite("OCRA-1:HOTP-SHA256-6:QA10-T1M")).toEqual({
      value: "OCRA-1:HOTP-SHA256-6:QA10-T1M",
      version: 1,
      algorithm: "SHA-256",
      digits: 6,
      counter: false,
      challenge: { format: "A", length: 10 },
      timestamp: { unit: "M", count: 1, seconds: 60 },
    });

    // Note the single-digit challenge length, as printed in the RFC.
    expect(parseOCRASuite("OCRA-1:HOTP-SHA1-4:QH8-S512")).toEqual({
      value: "OCRA-1:HOTP-SHA1-4:QH8-S512",
      version: 1,
      algorithm: "SHA-1",
      digits: 4,
      counter: false,
      challenge: { format: "H", length: 8 },
      session: { bytes: 512 },
    });
  });

  it("parses every optional component at once", () => {
    const suite = parseOCRASuite("OCRA-1:HOTP-SHA256-8:C-QA64-PSHA256-S128-T20S");
    expect(suite.counter).toBe(true);
    expect(suite.challenge).toEqual({ format: "A", length: 64 });
    expect(suite.password).toEqual({ algorithm: "SHA-256", bytes: 32 });
    expect(suite.session).toEqual({ bytes: 128 });
    expect(suite.timestamp).toEqual({ unit: "S", count: 20, seconds: 20 });
  });

  it("scales every time-step unit", () => {
    expect(parseOCRASuite("OCRA-1:HOTP-SHA1-6:QN08-T59S").timestamp?.seconds).toBe(59);
    expect(parseOCRASuite("OCRA-1:HOTP-SHA1-6:QN08-T5M").timestamp?.seconds).toBe(300);
    expect(parseOCRASuite("OCRA-1:HOTP-SHA1-6:QN08-T48H").timestamp?.seconds).toBe(172800);
  });

  it("applies the documented defaults for a bare S and T", () => {
    expect(parseOCRASuite("OCRA-1:HOTP-SHA1-6:QN08-S").session).toEqual({ bytes: 64 });
    expect(parseOCRASuite("OCRA-1:HOTP-SHA1-6:QN08-T").timestamp).toEqual({
      unit: "M",
      count: 1,
      seconds: 60,
    });
  });

  it("accepts t=0, meaning no truncation", () => {
    expect(parseOCRASuite("OCRA-1:HOTP-SHA1-0:QN08").digits).toBe(0);
  });

  it("parses case-insensitively but preserves the string verbatim", () => {
    const suite = parseOCRASuite("ocra-1:hotp-sha256-8:c-qn08-psha1");
    expect(suite.algorithm).toBe("SHA-256");
    expect(suite.challenge.format).toBe("N");
    expect(suite.password?.algorithm).toBe("SHA-1");
    // The suite is hashed as part of DataInput, so its bytes must not change.
    expect(suite.value).toBe("ocra-1:hotp-sha256-8:c-qn08-psha1");
  });

  it("rejects a suite that is not three colon-separated parts", () => {
    for (const invalid of ["", "OCRA-1:HOTP-SHA1-6", "OCRA-1:HOTP-SHA1-6:QN08:extra"]) {
      expect(() => parseOCRASuite(invalid)).toThrow(TOTPError);
    }
    // @ts-expect-error exercising the runtime guard for untyped callers
    expect(() => parseOCRASuite(null)).toThrow(/non-empty string/);
  });

  it("rejects an unknown algorithm component or version", () => {
    expect(() => parseOCRASuite("OATH-1:HOTP-SHA1-6:QN08")).toThrow(/OCRA-v/);
    expect(() => parseOCRASuite("OCRA-2:HOTP-SHA1-6:QN08")).toThrow(/version 2/);
  });

  it("rejects an unsupported CryptoFunction", () => {
    for (const invalid of [
      "OCRA-1:TOTP-SHA1-6:QN08",
      "OCRA-1:HOTP-MD5-6:QN08",
      "OCRA-1:HOTP-SHA1:QN08",
    ]) {
      expect(() => parseOCRASuite(invalid)).toThrow(/CryptoFunction/);
    }
  });

  it("rejects truncation lengths outside 0 and 4-10", () => {
    for (const digits of [1, 3, 11, 99]) {
      expect(() => parseOCRASuite(`OCRA-1:HOTP-SHA1-${digits}:QN08`)).toThrow(/truncation/);
    }
  });

  it("requires the mandatory challenge component", () => {
    expect(() => parseOCRASuite("OCRA-1:HOTP-SHA1-6:C")).toThrow(/mandatory challenge/);
    expect(() => parseOCRASuite("OCRA-1:HOTP-SHA1-6:")).toThrow(/mandatory challenge/);
    expect(() => parseOCRASuite("OCRA-1:HOTP-SHA1-6:QX08")).toThrow(/mandatory challenge/);
  });

  it("rejects challenge lengths outside 4-64", () => {
    expect(() => parseOCRASuite("OCRA-1:HOTP-SHA1-6:QN03")).toThrow(/Challenge length/);
    expect(() => parseOCRASuite("OCRA-1:HOTP-SHA1-6:QN65")).toThrow(/Challenge length/);
  });

  it("rejects malformed optional components", () => {
    expect(() => parseOCRASuite("OCRA-1:HOTP-SHA1-6:QN08-PMD5")).toThrow(/password component/);
    expect(() => parseOCRASuite("OCRA-1:HOTP-SHA1-6:QN08-S64")).toThrow(/session component/);
    expect(() => parseOCRASuite("OCRA-1:HOTP-SHA1-6:QN08-S000")).toThrow(/001-512/);
    expect(() => parseOCRASuite("OCRA-1:HOTP-SHA1-6:QN08-S513")).toThrow(/001-512/);
    expect(() => parseOCRASuite("OCRA-1:HOTP-SHA1-6:QN08-T1D")).toThrow(/timestamp component/);
    expect(() => parseOCRASuite("OCRA-1:HOTP-SHA1-6:QN08-T0S")).toThrow(/Time step/);
    expect(() => parseOCRASuite("OCRA-1:HOTP-SHA1-6:QN08-T60M")).toThrow(/Time step/);
    expect(() => parseOCRASuite("OCRA-1:HOTP-SHA1-6:QN08-T49H")).toThrow(/Time step/);
  });

  it("rejects components that are out of order or unknown", () => {
    expect(() => parseOCRASuite("OCRA-1:HOTP-SHA1-6:QN08-C")).toThrow(/Unexpected DataInput/);
    expect(() => parseOCRASuite("OCRA-1:HOTP-SHA1-6:QN08-T1M-PSHA1")).toThrow(/Unexpected DataInput/);
    expect(() => parseOCRASuite("OCRA-1:HOTP-SHA1-6:QN08-X")).toThrow(/Unexpected DataInput/);
  });

  it("reports every failure as a TOTPError with the INVALID_SUITE code", () => {
    try {
      parseOCRASuite("nonsense");
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(TOTPError);
      expect((error as TOTPError).code).toBe("INVALID_SUITE");
    }
  });
});
