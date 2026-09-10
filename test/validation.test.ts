import { describe, expect, it } from "vitest";
import {
  TOTPError,
  generateHOTP,
  generateTOTP,
  verifyHOTP,
  verifyTOTP,
} from "../src/index.js";

const SECRET = "JBSWY3DPEHPK3PXP";

/** Asserts the thrown error is a TOTPError carrying the given code. */
async function expectCode(promise: Promise<unknown> | (() => unknown), code: string) {
  const run = typeof promise === "function" ? Promise.resolve().then(promise) : promise;
  await expect(run).rejects.toMatchObject({ name: "TOTPError", code });
}

describe("input validation", () => {
  it("rejects an empty or malformed secret", async () => {
    await expectCode(generateTOTP({ secret: "" }), "INVALID_SECRET");
    await expectCode(generateTOTP({ secret: new Uint8Array(0) }), "INVALID_SECRET");
    await expectCode(generateTOTP({ secret: "!!!!" }), "INVALID_SECRET");
    // @ts-expect-error exercising the runtime guard for untyped callers
    await expectCode(generateTOTP({ secret: 42 }), "INVALID_SECRET");
  });

  it("rejects digit counts outside 1-10", async () => {
    for (const digits of [0, 11, 6.5, Number.NaN]) {
      await expectCode(generateTOTP({ secret: SECRET, digits }), "INVALID_DIGITS");
    }
    await expect(generateTOTP({ secret: SECRET, digits: 10, timestamp: 0 })).resolves.toHaveLength(10);
  });

  it("rejects a non-positive or fractional period", async () => {
    for (const period of [0, -30, 7.5]) {
      await expectCode(generateTOTP({ secret: SECRET, period }), "INVALID_PERIOD");
    }
  });

  it("rejects a non-finite timestamp", async () => {
    await expectCode(generateTOTP({ secret: SECRET, timestamp: Number.NaN }), "INVALID_PERIOD");
    await expectCode(generateTOTP({ secret: SECRET, timestamp: Infinity }), "INVALID_PERIOD");
  });

  it("rejects an unknown algorithm", async () => {
    // @ts-expect-error exercising the runtime guard for untyped callers
    await expectCode(generateTOTP({ secret: SECRET, algorithm: "MD5" }), "INVALID_ALGORITHM");
  });

  it("rejects a negative or unsafe counter", async () => {
    await expectCode(generateHOTP({ secret: SECRET, counter: -1 }), "INVALID_COUNTER");
    await expectCode(generateHOTP({ secret: SECRET, counter: 2n ** 64n }), "INVALID_COUNTER");
    await expectCode(generateHOTP({ secret: SECRET, counter: 1.5 }), "INVALID_COUNTER");
    await expectCode(
      generateHOTP({ secret: SECRET, counter: Number.MAX_SAFE_INTEGER + 2 }),
      "INVALID_COUNTER",
    );
  });

  it("accepts the largest 64-bit counter", async () => {
    await expect(generateHOTP({ secret: SECRET, counter: 2n ** 64n - 1n })).resolves.toMatch(/^\d{6}$/);
  });

  it("rejects a negative or fractional window", async () => {
    await expectCode(verifyTOTP({ secret: SECRET, token: "000000", window: -1 }), "INVALID_WINDOW");
    await expectCode(
      verifyHOTP({ secret: SECRET, counter: 0, token: "000000", window: 1.5 }),
      "INVALID_WINDOW",
    );
  });

  it("throws on bad options rather than quietly failing verification", async () => {
    // A misconfigured call must not be indistinguishable from a wrong code.
    await expectCode(verifyTOTP({ secret: SECRET, token: "000000", digits: 0 }), "INVALID_DIGITS");
    await expectCode(verifyTOTP({ secret: "", token: "000000" }), "INVALID_SECRET");
    await expectCode(verifyTOTP({ secret: SECRET, token: "000000", period: 0 }), "INVALID_PERIOD");
  });

  it("exposes TOTPError as a real Error subclass", async () => {
    const error = await generateTOTP({ secret: "" }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(TOTPError);
    expect(error).toBeInstanceOf(Error);
    expect((error as TOTPError).code).toBe("INVALID_SECRET");
  });
});
