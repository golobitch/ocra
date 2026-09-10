import { describe, expect, it, vi, afterEach } from "vitest";
import {
  TOTPError,
  generateOCRA,
  hashOCRAPassword,
  hexDecode,
  hexEncode,
  ocraTimeSteps,
  parseOCRASuite,
  utf8Decode,
  verifyOCRA,
  verifyOCRADelta,
} from "../src/index.js";

const KEY20 = hexDecode("3132333435363738393031323334353637383930");
const PIN_SHA1 = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220";

afterEach(() => {
  vi.useRealTimers();
});

/** Asserts a rejected promise carries the given TOTPError code. */
async function expectCode(promise: Promise<unknown>, code: string) {
  await expect(promise).rejects.toMatchObject({ name: "TOTPError", code });
}

describe("challenge encoding", () => {
  it("accepts an already-parsed suite as well as a string", async () => {
    const parsed = parseOCRASuite("OCRA-1:HOTP-SHA1-6:QN08");
    await expect(generateOCRA({ suite: parsed, secret: KEY20, question: "00000000" })).resolves.toBe(
      "237653",
    );
  });

  it("treats an array of challenges as their concatenation", async () => {
    const suite = "OCRA-1:HOTP-SHA1-6:QA20";
    const parts = await generateOCRA({ suite, secret: KEY20, question: ["ABCD", "EFGH"] });
    const joined = await generateOCRA({ suite, secret: KEY20, question: "ABCDEFGH" });
    expect(parts).toBe(joined);
  });

  it("accepts raw bytes as the challenge", async () => {
    const suite = "OCRA-1:HOTP-SHA1-6:QA08";
    const fromBytes = await generateOCRA({ suite, secret: KEY20, question: utf8Decode("SIG10000") });
    const fromText = await generateOCRA({ suite, secret: KEY20, question: "SIG10000" });
    expect(fromBytes).toBe(fromText);
  });

  it("reads a numeric challenge as a decimal number, not as its digits", async () => {
    // "00000000" and "0" are the same number, so they must produce the same Q.
    const suite = "OCRA-1:HOTP-SHA1-6:QN08";
    const padded = await generateOCRA({ suite, secret: KEY20, question: "00000000" });
    const bare = await generateOCRA({ suite, secret: KEY20, question: "0000" });
    expect(bare).toBe(padded);
  });

  it("keeps the trailing nibble of an odd-length numeric challenge", async () => {
    // 22222222 -> 0x1531d74, seven nibbles: the eighth comes from the padding.
    const suite = "OCRA-1:HOTP-SHA1-6:QN08";
    expect(BigInt("22222222").toString(16)).toHaveLength(7);
    await expect(generateOCRA({ suite, secret: KEY20, question: "22222222" })).resolves.toBe(
      "653583",
    );
  });

  it("accepts a hexadecimal challenge in either case", async () => {
    const suite = "OCRA-1:HOTP-SHA1-6:QH08";
    const lower = await generateOCRA({ suite, secret: KEY20, question: "deadbeef" });
    const upper = await generateOCRA({ suite, secret: KEY20, question: "DEADBEEF" });
    expect(lower).toBe(upper);
  });

  it("rejects a challenge that does not match the suite's format", async () => {
    await expectCode(
      generateOCRA({ suite: "OCRA-1:HOTP-SHA1-6:QN08", secret: KEY20, question: "1234abcd" }),
      "INVALID_CHALLENGE",
    );
    await expectCode(
      generateOCRA({ suite: "OCRA-1:HOTP-SHA1-6:QH08", secret: KEY20, question: "nothex!!" }),
      "INVALID_CHALLENGE",
    );
  });

  it("rejects an empty or missing challenge", async () => {
    const suite = "OCRA-1:HOTP-SHA1-6:QN08";
    await expectCode(generateOCRA({ suite, secret: KEY20, question: "" }), "INVALID_CHALLENGE");
    await expectCode(generateOCRA({ suite, secret: KEY20, question: [] }), "INVALID_CHALLENGE");
    await expectCode(
      generateOCRA({ suite, secret: KEY20, question: new Uint8Array(0) }),
      "INVALID_CHALLENGE",
    );
    // @ts-expect-error exercising the runtime guard for untyped callers
    await expectCode(generateOCRA({ suite, secret: KEY20, question: 12345678 }), "INVALID_CHALLENGE");
    await expectCode(generateOCRA({ suite, secret: KEY20, question: [""] }), "INVALID_CHALLENGE");
  });

  it("rejects a challenge that will not fit the 128-byte Q field", async () => {
    await expectCode(
      generateOCRA({
        suite: "OCRA-1:HOTP-SHA1-6:QA64",
        secret: KEY20,
        question: new Uint8Array(129),
      }),
      "INVALID_CHALLENGE",
    );
  });

  it("length-checks each part of a multi-part challenge against the suite", async () => {
    await expectCode(
      generateOCRA({
        suite: "OCRA-1:HOTP-SHA256-8:QA08",
        secret: KEY20,
        question: ["CLI222201234", "SRV11110"],
      }),
      "INVALID_CHALLENGE",
    );
  });
});

describe("DataInput parameters", () => {
  it("requires exactly the parameters the suite declares", async () => {
    const secret = KEY20;
    await expectCode(
      generateOCRA({ suite: "OCRA-1:HOTP-SHA1-6:C-QN08", secret, question: "0" }),
      "INVALID_PARAMETER",
    );
    await expectCode(
      generateOCRA({ suite: "OCRA-1:HOTP-SHA1-6:QN08-PSHA1", secret, question: "0" }),
      "INVALID_PARAMETER",
    );
    await expectCode(
      generateOCRA({ suite: "OCRA-1:HOTP-SHA1-6:QN08-S064", secret, question: "0" }),
      "INVALID_PARAMETER",
    );
  });

  it("rejects parameters the suite has no field for, rather than ignoring them", async () => {
    const suite = "OCRA-1:HOTP-SHA1-6:QN08";
    await expectCode(
      generateOCRA({ suite, secret: KEY20, question: "0", counter: 1 }),
      "INVALID_PARAMETER",
    );
    await expectCode(
      generateOCRA({ suite, secret: KEY20, question: "0", passwordHash: PIN_SHA1 }),
      "INVALID_PARAMETER",
    );
    await expectCode(
      generateOCRA({ suite, secret: KEY20, question: "0", session: "abc" }),
      "INVALID_PARAMETER",
    );
  });

  it("accepts the password hash as bytes or hex", async () => {
    const suite = "OCRA-1:HOTP-SHA1-6:QN08-PSHA1";
    const fromHex = await generateOCRA({ suite, secret: KEY20, question: "0", passwordHash: PIN_SHA1 });
    const fromBytes = await generateOCRA({
      suite,
      secret: KEY20,
      question: "0",
      passwordHash: hexDecode(PIN_SHA1),
    });
    expect(fromBytes).toBe(fromHex);
  });

  it("rejects a password hash of the wrong length", async () => {
    const suite = "OCRA-1:HOTP-SHA1-6:QN08-PSHA1";
    await expectCode(
      generateOCRA({ suite, secret: KEY20, question: "0", passwordHash: "7110eda4" }),
      "INVALID_PASSWORD",
    );
    // A SHA-256 digest supplied where the suite asks for SHA-1.
    await expectCode(
      generateOCRA({
        suite,
        secret: KEY20,
        question: "0",
        passwordHash: await hashOCRAPassword("1234", "SHA-256"),
      }),
      "INVALID_PASSWORD",
    );
    await expectCode(
      // @ts-expect-error exercising the runtime guard for untyped callers
      generateOCRA({ suite, secret: KEY20, question: "0", passwordHash: 1234 }),
      "INVALID_PASSWORD",
    );
  });

  it("hashes passwords with each supported algorithm", async () => {
    expect(await hashOCRAPassword("1234")).toHaveLength(20);
    expect(await hashOCRAPassword("1234", "SHA-256")).toHaveLength(32);
    expect(await hashOCRAPassword(utf8Decode("1234"), "SHA512")).toHaveLength(64);
  });

  it("right-aligns session information in its fixed-length field", async () => {
    // The reference implementation left-pads S, so a short value and the same
    // value already right-aligned in the field must agree.
    const suite = "OCRA-1:HOTP-SHA1-6:QN08-S064";
    const short = await generateOCRA({ suite, secret: KEY20, question: "0", session: "abc" });

    const padded = new Uint8Array(64);
    padded.set(utf8Decode("abc"), 61);
    const explicit = await generateOCRA({ suite, secret: KEY20, question: "0", session: padded });

    expect(short).toBe(explicit);
  });

  it("rejects session information that overflows its field", async () => {
    await expectCode(
      generateOCRA({
        suite: "OCRA-1:HOTP-SHA1-6:QN08-S064",
        secret: KEY20,
        question: "0",
        session: new Uint8Array(65),
      }),
      "INVALID_SESSION",
    );
    await expectCode(
      // @ts-expect-error exercising the runtime guard for untyped callers
      generateOCRA({ suite: "OCRA-1:HOTP-SHA1-6:QN08-S064", secret: KEY20, question: "0", session: 5 }),
      "INVALID_SESSION",
    );
  });

  it("rejects an unsafe counter", async () => {
    await expectCode(
      generateOCRA({
        suite: "OCRA-1:HOTP-SHA1-6:C-QN08",
        secret: KEY20,
        question: "0",
        counter: 1.5,
      }),
      "INVALID_COUNTER",
    );
  });

  it("rejects a non-finite timestamp", async () => {
    await expectCode(
      generateOCRA({
        suite: "OCRA-1:HOTP-SHA1-6:QN08-T1M",
        secret: KEY20,
        question: "0",
        timestamp: Number.NaN,
      }),
      "INVALID_PARAMETER",
    );
  });
});

describe("truncation", () => {
  it("returns the full HMAC as hex when the suite asks for no truncation", async () => {
    const value = await generateOCRA({
      suite: "OCRA-1:HOTP-SHA1-0:QN08",
      secret: KEY20,
      question: "00000000",
    });
    expect(value).toMatch(/^[0-9a-f]{40}$/);

    const sha512 = await generateOCRA({
      suite: "OCRA-1:HOTP-SHA512-0:QN08",
      secret: KEY20,
      question: "00000000",
    });
    expect(sha512).toHaveLength(128);
  });

  it("verifies an untruncated response", async () => {
    const suite = "OCRA-1:HOTP-SHA1-0:QN08";
    const response = await generateOCRA({ suite, secret: KEY20, question: "00000000" });
    await expect(verifyOCRA({ suite, secret: KEY20, question: "00000000", response })).resolves.toBe(
      true,
    );
    await expect(
      verifyOCRA({ suite, secret: KEY20, question: "00000000", response: hexEncode(new Uint8Array(20)) }),
    ).resolves.toBe(false);
  });

  it("produces every permitted truncation length", async () => {
    for (const digits of [4, 6, 8, 10]) {
      const value = await generateOCRA({
        suite: `OCRA-1:HOTP-SHA1-${digits}:QN08`,
        secret: KEY20,
        question: "00000000",
      });
      expect(value).toHaveLength(digits);
    }
  });
});

describe("verifyOCRA", () => {
  const suite = "OCRA-1:HOTP-SHA1-6:QN08";

  it("rejects a response of the wrong length without hashing", async () => {
    await expect(
      verifyOCRA({ suite, secret: KEY20, question: "00000000", response: "23765" }),
    ).resolves.toBe(false);
    // @ts-expect-error exercising the runtime guard for untyped callers
    await expect(verifyOCRA({ suite, secret: KEY20, question: "0", response: null })).resolves.toBe(
      false,
    );
  });

  it("reports no offsets for a suite without C or T", async () => {
    await expect(
      verifyOCRADelta({ suite, secret: KEY20, question: "00000000", response: "237653" }),
    ).resolves.toEqual({ counter: 0, time: 0 });
  });

  it("ignores a window over a field the suite does not carry", async () => {
    await expect(
      verifyOCRADelta({
        suite,
        secret: KEY20,
        question: "00000000",
        response: "237653",
        counterWindow: 5,
        timeWindow: 5,
      }),
    ).resolves.toEqual({ counter: 0, time: 0 });
  });

  it("never looks backwards on a counter suite", async () => {
    const counterSuite = "OCRA-1:HOTP-SHA1-6:C-QN08";
    const response = await generateOCRA({
      suite: counterSuite,
      secret: KEY20,
      question: "00000000",
      counter: 2,
    });
    await expect(
      verifyOCRADelta({
        suite: counterSuite,
        secret: KEY20,
        question: "00000000",
        counter: 5,
        response,
        counterWindow: 10,
      }),
    ).resolves.toBeNull();
  });

  it("skips time steps that fall before the epoch", async () => {
    const timeSuite = "OCRA-1:HOTP-SHA1-6:QN08-T1M";
    await expect(
      verifyOCRADelta({
        suite: timeSuite,
        secret: KEY20,
        question: "00000000",
        response: "000000",
        timestamp: 0,
        timeWindow: 3,
      }),
    ).resolves.toBeNull();
  });

  it("requires the counter on a C suite instead of assuming zero", async () => {
    const counterSuite = "OCRA-1:HOTP-SHA1-6:C-QN08";
    const atZero = await generateOCRA({
      suite: counterSuite,
      secret: KEY20,
      question: "00000000",
      counter: 0,
    });
    await expectCode(
      verifyOCRA({ suite: counterSuite, secret: KEY20, question: "00000000", response: atZero }),
      "INVALID_PARAMETER",
    );
  });

  it("accepts a Date as the timestamp", async () => {
    const timeSuite = "OCRA-1:HOTP-SHA1-6:QN08-T1M";
    const at = new Date(0x132d0b6 * 60 * 1000);
    const fromDate = await generateOCRA({ suite: timeSuite, secret: KEY20, question: "0", timestamp: at });
    const fromMillis = await generateOCRA({
      suite: timeSuite,
      secret: KEY20,
      question: "0",
      timestamp: at.getTime(),
    });
    expect(fromDate).toBe(fromMillis);
  });

  it("rejects a negative window", async () => {
    await expectCode(
      verifyOCRA({
        suite: "OCRA-1:HOTP-SHA1-6:C-QN08",
        secret: KEY20,
        question: "0",
        counter: 0,
        response: "000000",
        counterWindow: -1,
      }),
      "INVALID_WINDOW",
    );
  });

  it("defaults the timestamp to now", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0x132d0b6 * 60 * 1000);
    const timeSuite = "OCRA-1:HOTP-SHA512-8:QN08-T1M";
    const key64 = hexDecode(
      "31323334353637383930313233343536373839303132333435363738393031323334353637383930" +
        "313233343536373839303132333435363738393031323334",
    );
    await expect(
      generateOCRA({ suite: timeSuite, secret: key64, question: "00000000" }),
    ).resolves.toBe("95209754");
  });
});

describe("ocraTimeSteps", () => {
  it("counts steps of the suite's granularity", () => {
    expect(ocraTimeSteps("OCRA-1:HOTP-SHA1-6:QN08-T1M", 60_000)).toBe(1n);
    expect(ocraTimeSteps("OCRA-1:HOTP-SHA1-6:QN08-T20S", 60_000)).toBe(3n);
    expect(ocraTimeSteps("OCRA-1:HOTP-SHA1-6:QN08-T24H", 86_400_000)).toBe(1n);
  });

  it("defaults to the current time", () => {
    vi.useFakeTimers();
    vi.setSystemTime(120_000);
    expect(ocraTimeSteps("OCRA-1:HOTP-SHA1-6:QN08-T1M")).toBe(2n);
  });

  it("throws for a suite with no T component", () => {
    expect(() => ocraTimeSteps("OCRA-1:HOTP-SHA1-6:QN08")).toThrow(TOTPError);
    expect(() => ocraTimeSteps("OCRA-1:HOTP-SHA1-6:QN08")).toThrow(/no T component/);
  });
});
