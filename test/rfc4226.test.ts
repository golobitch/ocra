import { describe, expect, it } from "vitest";
import { generateHOTP, utf8Decode, verifyHOTP, verifyHOTPDelta } from "../src/index.js";

/** RFC 4226 Appendix D uses the ASCII secret "12345678901234567890". */
const SECRET = utf8Decode("12345678901234567890");

/** RFC 4226 Appendix D, Table 1: HOTP values for counters 0-9. */
const VECTORS = [
  { counter: 0, hex: "4c93cf18", decimal: 1284755224, hotp: "755224" },
  { counter: 1, hex: "41397eea", decimal: 1094287082, hotp: "287082" },
  { counter: 2, hex: "82fef30", decimal: 137359152, hotp: "359152" },
  { counter: 3, hex: "66ef7655", decimal: 1726969429, hotp: "969429" },
  { counter: 4, hex: "61c5938a", decimal: 1640338314, hotp: "338314" },
  { counter: 5, hex: "33c083d4", decimal: 868254676, hotp: "254676" },
  { counter: 6, hex: "7256c032", decimal: 1918287922, hotp: "287922" },
  { counter: 7, hex: "4e5b397", decimal: 82162583, hotp: "162583" },
  { counter: 8, hex: "2823443f", decimal: 673399871, hotp: "399871" },
  { counter: 9, hex: "2679dc69", decimal: 645520489, hotp: "520489" },
] as const;

describe("RFC 4226 Appendix D test vectors", () => {
  it.each(VECTORS)("counter $counter produces $hotp", async ({ counter, hotp }) => {
    await expect(generateHOTP({ secret: SECRET, counter })).resolves.toBe(hotp);
  });

  it.each(VECTORS)(
    "counter $counter truncates to the documented integer $decimal",
    async ({ counter, decimal, hex }) => {
      // A 10-digit code is the full 31-bit dynamic-truncation value, so this
      // checks truncation independently of the final modulo.
      const full = await generateHOTP({ secret: SECRET, counter, digits: 10 });
      expect(Number(full)).toBe(decimal);
      expect(Number(full).toString(16)).toBe(hex);
    },
  );

  it("accepts bigint counters", async () => {
    await expect(generateHOTP({ secret: SECRET, counter: 3n })).resolves.toBe("969429");
  });
});

describe("verifyHOTP", () => {
  it("accepts the code for the expected counter", async () => {
    await expect(verifyHOTP({ secret: SECRET, counter: 5, token: "254676" })).resolves.toBe(true);
  });

  it("rejects a code from a different counter when the window is 0", async () => {
    await expect(verifyHOTP({ secret: SECRET, counter: 5, token: "287922" })).resolves.toBe(false);
  });

  it("resynchronizes forward within the window", async () => {
    await expect(
      verifyHOTPDelta({ secret: SECRET, counter: 5, token: "399871", window: 3 }),
    ).resolves.toBe(3);
  });

  it("never looks backwards, however large the window", async () => {
    await expect(
      verifyHOTPDelta({ secret: SECRET, counter: 5, token: "338314", window: 10 }),
    ).resolves.toBeNull();
  });

  it("reports an exact match as delta 0", async () => {
    await expect(
      verifyHOTPDelta({ secret: SECRET, counter: 2, token: "359152", window: 5 }),
    ).resolves.toBe(0);
  });

  it("rejects a non-string token without hashing", async () => {
    // @ts-expect-error exercising the runtime guard for untyped callers
    await expect(verifyHOTP({ secret: SECRET, counter: 0, token: null })).resolves.toBe(false);
  });

  it("rejects a code just past the window", async () => {
    await expect(
      verifyHOTPDelta({ secret: SECRET, counter: 0, token: "287082", window: 0 }),
    ).resolves.toBeNull();
  });
});
