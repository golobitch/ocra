import { afterEach, describe, expect, it, vi } from "vitest";
import {
  TOTPError,
  generateTOTP,
  timeRemaining,
  totpCounter,
  verifyTOTP,
  verifyTOTPDelta,
} from "../src/index.js";

const SECRET = "JBSWY3DPEHPK3PXP";

afterEach(() => {
  vi.useRealTimers();
});

describe("generateTOTP", () => {
  it("defaults to the current time", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(1234567890 * 1000));

    const implicit = await generateTOTP({ secret: SECRET });
    const explicit = await generateTOTP({ secret: SECRET, timestamp: 1234567890 * 1000 });
    expect(implicit).toBe(explicit);
  });

  it("holds the code steady across a time step and changes at the boundary", async () => {
    const start = 1_700_000_010_000; // exactly on a 30s step boundary
    const withinStep = await generateTOTP({ secret: SECRET, timestamp: start });
    const lateInStep = await generateTOTP({ secret: SECRET, timestamp: start + 29_999 });
    const nextStep = await generateTOTP({ secret: SECRET, timestamp: start + 30_000 });

    expect(lateInStep).toBe(withinStep);
    expect(nextStep).not.toBe(withinStep);
  });

  it("pads codes that fall below the digit count", async () => {
    // A code whose truncated value starts with zeros must keep its length.
    const codes = await Promise.all(
      Array.from({ length: 200 }, (_, i) => generateTOTP({ secret: SECRET, timestamp: i * 30_000 })),
    );
    expect(codes.every((code) => /^\d{6}$/.test(code))).toBe(true);
  });

  it("honours a non-default period", async () => {
    const a = await generateTOTP({ secret: SECRET, timestamp: 60_000, period: 60 });
    const b = await generateTOTP({ secret: SECRET, timestamp: 119_000, period: 60 });
    const c = await generateTOTP({ secret: SECRET, timestamp: 120_000, period: 60 });
    expect(b).toBe(a);
    expect(c).not.toBe(a);
  });

  it("honours a non-zero epoch", async () => {
    const epoch = 1_000_000_000_000;
    const shifted = await generateTOTP({ secret: SECRET, timestamp: epoch + 90_000, epoch });
    const unshifted = await generateTOTP({ secret: SECRET, timestamp: 90_000 });
    expect(shifted).toBe(unshifted);
  });

  it("produces the same code for a base32 string and its decoded bytes", async () => {
    const bytes = new Uint8Array([72, 101, 108, 108, 111, 33, 222, 173, 190, 239]);
    const fromBytes = await generateTOTP({ secret: bytes, timestamp: 0 });
    const fromBase32 = await generateTOTP({ secret: SECRET, timestamp: 0 });
    expect(fromBytes).toBe(fromBase32);
  });

  it("is unaffected by a Uint8Array that is a view onto a larger buffer", async () => {
    const backing = new Uint8Array([0xff, 0xff, 72, 101, 108, 108, 111, 33, 222, 173, 190, 239, 0xff]);
    const view = backing.subarray(2, 12);
    await expect(generateTOTP({ secret: view, timestamp: 0 })).resolves.toBe(
      await generateTOTP({ secret: SECRET, timestamp: 0 }),
    );
  });
});

describe("verifyTOTP", () => {
  const now = 1_700_000_000_000;

  it("accepts the current code", async () => {
    const token = await generateTOTP({ secret: SECRET, timestamp: now });
    await expect(verifyTOTP({ secret: SECRET, token, timestamp: now })).resolves.toBe(true);
  });

  it("rejects a code generated from a different secret", async () => {
    const token = await generateTOTP({ secret: "GEZDGNBVGY3TQOJQ", timestamp: now });
    await expect(verifyTOTP({ secret: SECRET, token, timestamp: now })).resolves.toBe(false);
  });

  it("accepts one step of drift in either direction by default", async () => {
    const past = await generateTOTP({ secret: SECRET, timestamp: now - 30_000 });
    const future = await generateTOTP({ secret: SECRET, timestamp: now + 30_000 });

    await expect(verifyTOTPDelta({ secret: SECRET, token: past, timestamp: now })).resolves.toBe(-1);
    await expect(verifyTOTPDelta({ secret: SECRET, token: future, timestamp: now })).resolves.toBe(1);
  });

  it("rejects drift beyond the window", async () => {
    const stale = await generateTOTP({ secret: SECRET, timestamp: now - 60_000 });
    await expect(verifyTOTP({ secret: SECRET, token: stale, timestamp: now })).resolves.toBe(false);
    await expect(
      verifyTOTP({ secret: SECRET, token: stale, timestamp: now, window: 2 }),
    ).resolves.toBe(true);
  });

  it("accepts nothing but the current step when window is 0", async () => {
    const past = await generateTOTP({ secret: SECRET, timestamp: now - 30_000 });
    await expect(
      verifyTOTP({ secret: SECRET, token: past, timestamp: now, window: 0 }),
    ).resolves.toBe(false);
  });

  it("reports the nearest matching step first", async () => {
    const token = await generateTOTP({ secret: SECRET, timestamp: now });
    await expect(
      verifyTOTPDelta({ secret: SECRET, token, timestamp: now, window: 10 }),
    ).resolves.toBe(0);
  });

  it("rejects tokens of the wrong length without matching", async () => {
    const token = await generateTOTP({ secret: SECRET, timestamp: now });
    await expect(verifyTOTP({ secret: SECRET, token: token.slice(1), timestamp: now })).resolves.toBe(false);
    await expect(verifyTOTP({ secret: SECRET, token: `0${token}`, timestamp: now })).resolves.toBe(false);
  });

  it("rejects empty and non-numeric tokens", async () => {
    for (const token of ["", "      ", "abcdef", "12 456"]) {
      await expect(verifyTOTP({ secret: SECRET, token, timestamp: now })).resolves.toBe(false);
    }
  });

  it("does not clamp below counter 0 near the epoch", async () => {
    const token = await generateTOTP({ secret: SECRET, timestamp: 0 });
    await expect(verifyTOTPDelta({ secret: SECRET, token, timestamp: 0, window: 5 })).resolves.toBe(0);
  });

  it("skips the counters a window would push below 0 instead of throwing", async () => {
    // The window reaches back past the epoch; those steps must be skipped, and
    // the forward steps still checked.
    await expect(
      verifyTOTPDelta({ secret: SECRET, token: "000000", timestamp: 0, window: 5 }),
    ).resolves.toBeNull();

    const future = await generateTOTP({ secret: SECRET, timestamp: 60_000 });
    await expect(
      verifyTOTPDelta({ secret: SECRET, token: future, timestamp: 0, window: 5 }),
    ).resolves.toBe(2);
  });

  it("rejects a non-string token without hashing", async () => {
    // @ts-expect-error exercising the runtime guard for untyped callers
    await expect(verifyTOTP({ secret: SECRET, token: 123456, timestamp: now })).resolves.toBe(false);
    // @ts-expect-error exercising the runtime guard for untyped callers
    await expect(verifyTOTP({ secret: SECRET, token: null, timestamp: now })).resolves.toBe(false);
  });
});

describe("totpCounter", () => {
  it("counts whole periods since the epoch", () => {
    expect(totpCounter({ timestamp: 0 })).toBe(0n);
    expect(totpCounter({ timestamp: 29_999 })).toBe(0n);
    expect(totpCounter({ timestamp: 30_000 })).toBe(1n);
    expect(totpCounter({ timestamp: 59_000, period: 30 })).toBe(1n);
  });

  it("rejects timestamps before the epoch", () => {
    expect(() => totpCounter({ timestamp: 1000, epoch: 30_000 })).toThrow(TOTPError);
  });
});

describe("timeRemaining", () => {
  it("counts down to the end of the current step", () => {
    expect(timeRemaining({ timestamp: 0 })).toBe(30_000);
    expect(timeRemaining({ timestamp: 10_000 })).toBe(20_000);
    expect(timeRemaining({ timestamp: 29_999 })).toBe(1);
    expect(timeRemaining({ timestamp: 30_000 })).toBe(30_000);
  });

  it("honours the period", () => {
    expect(timeRemaining({ timestamp: 10_000, period: 60 })).toBe(50_000);
  });

  it("defaults to the current time", () => {
    vi.useFakeTimers();
    vi.setSystemTime(45_000);
    expect(timeRemaining()).toBe(15_000);
  });

  it("stays positive before the epoch", () => {
    expect(timeRemaining({ timestamp: -1000 })).toBe(1000);
  });
});
