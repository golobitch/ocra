import { describe, expect, it } from "vitest";
import {
  generateOCRA,
  hashOCRAPassword,
  hexDecode,
  hexEncode,
  ocraTimeSteps,
  verifyOCRA,
  verifyOCRADelta,
} from "../src/index.js";

/** RFC 6287 Appendix C, "Standard 20Byte / 32Byte / 64Byte key". */
const KEY20 = hexDecode("3132333435363738393031323334353637383930");
const KEY32 = hexDecode("3132333435363738393031323334353637383930313233343536373839303132");
const KEY64 = hexDecode(
  "31323334353637383930313233343536373839303132333435363738393031323334353637383930" +
    "313233343536373839303132333435363738393031323334",
);

/** RFC 6287 Appendix C: SHA-1 hash of the PIN "1234". */
const PIN_SHA1 = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220";

/** Appendix C uses T = 0x132d0b6, a count of one-minute steps. */
const T_132D0B6 = 0x132d0b6 * 60 * 1000;

describe("RFC 6287 Appendix C.1 - one-way challenge response", () => {
  const suite1 = "OCRA-1:HOTP-SHA1-6:QN08";
  it.each([
    ["00000000", "237653"],
    ["11111111", "243178"],
    ["22222222", "653583"],
    ["33333333", "740991"],
    ["44444444", "608993"],
    ["55555555", "388898"],
    ["66666666", "816933"],
    ["77777777", "224598"],
    ["88888888", "750600"],
    ["99999999", "294470"],
  ])(`${suite1} Q=%s -> %s`, async (question, expected) => {
    await expect(generateOCRA({ suite: suite1, secret: KEY20, question })).resolves.toBe(expected);
  });

  const suite2 = "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1";
  it.each([
    [0, "65347737"],
    [1, "86775851"],
    [2, "78192410"],
    [3, "71565254"],
    [4, "10104329"],
    [5, "65983500"],
    [6, "70069104"],
    [7, "91771096"],
    [8, "75011558"],
    [9, "08522129"],
  ])(`${suite2} C=%i Q=12345678 -> %s`, async (counter, expected) => {
    const value = await generateOCRA({
      suite: suite2,
      secret: KEY32,
      counter,
      question: "12345678",
      passwordHash: PIN_SHA1,
    });
    expect(value).toBe(expected);
  });

  const suite3 = "OCRA-1:HOTP-SHA256-8:QN08-PSHA1";
  it.each([
    ["00000000", "83238735"],
    ["11111111", "01501458"],
    ["22222222", "17957585"],
    ["33333333", "86776967"],
    ["44444444", "86807031"],
  ])(`${suite3} Q=%s -> %s`, async (question, expected) => {
    const value = await generateOCRA({
      suite: suite3,
      secret: KEY32,
      question,
      passwordHash: PIN_SHA1,
    });
    expect(value).toBe(expected);
  });

  const suite4 = "OCRA-1:HOTP-SHA512-8:C-QN08";
  it.each([
    [0, "00000000", "07016083"],
    [1, "11111111", "63947962"],
    [2, "22222222", "70123924"],
    [3, "33333333", "25341727"],
    [4, "44444444", "33203315"],
    [5, "55555555", "34205738"],
    [6, "66666666", "44343969"],
    [7, "77777777", "51946085"],
    [8, "88888888", "20403879"],
    [9, "99999999", "31409299"],
  ])(`${suite4} C=%i Q=%s -> %s`, async (counter, question, expected) => {
    await expect(
      generateOCRA({ suite: suite4, secret: KEY64, counter, question }),
    ).resolves.toBe(expected);
  });

  const suite5 = "OCRA-1:HOTP-SHA512-8:QN08-T1M";
  it.each([
    ["00000000", "95209754"],
    ["11111111", "55907591"],
    ["22222222", "22048402"],
    ["33333333", "24218844"],
    ["44444444", "36209546"],
  ])(`${suite5} Q=%s T=132d0b6 -> %s`, async (question, expected) => {
    const value = await generateOCRA({
      suite: suite5,
      secret: KEY64,
      question,
      timestamp: T_132D0B6,
    });
    expect(value).toBe(expected);
  });
});

describe("RFC 6287 Appendix C.2 - mutual challenge-response", () => {
  const sha256 = "OCRA-1:HOTP-SHA256-8:QA08";
  it.each([
    ["CLI22220", "SRV11110", "28247970"],
    ["CLI22221", "SRV11111", "01984843"],
    ["CLI22222", "SRV11112", "65387857"],
    ["CLI22223", "SRV11113", "03351211"],
    ["CLI22224", "SRV11114", "83412541"],
  ])(`server ${sha256} Q=%s%s -> %s`, async (qc, qs, expected) => {
    await expect(
      generateOCRA({ suite: sha256, secret: KEY32, question: [qc, qs] }),
    ).resolves.toBe(expected);
  });

  it.each([
    ["SRV11110", "CLI22220", "15510767"],
    ["SRV11111", "CLI22221", "90175646"],
    ["SRV11112", "CLI22222", "33777207"],
    ["SRV11113", "CLI22223", "95285278"],
    ["SRV11114", "CLI22224", "28934924"],
  ])(`client ${sha256} Q=%s%s -> %s`, async (qs, qc, expected) => {
    await expect(
      generateOCRA({ suite: sha256, secret: KEY32, question: [qs, qc] }),
    ).resolves.toBe(expected);
  });

  const serverSuite = "OCRA-1:HOTP-SHA512-8:QA08";
  it.each([
    ["CLI22220", "SRV11110", "79496648"],
    ["CLI22221", "SRV11111", "76831980"],
    ["CLI22222", "SRV11112", "12250499"],
    ["CLI22223", "SRV11113", "90856481"],
    ["CLI22224", "SRV11114", "12761449"],
  ])(`server ${serverSuite} Q=%s%s -> %s`, async (qc, qs, expected) => {
    await expect(
      generateOCRA({ suite: serverSuite, secret: KEY64, question: [qc, qs] }),
    ).resolves.toBe(expected);
  });

  const clientSuite = "OCRA-1:HOTP-SHA512-8:QA08-PSHA1";
  it.each([
    ["SRV11110", "CLI22220", "18806276"],
    ["SRV11111", "CLI22221", "70020315"],
    ["SRV11112", "CLI22222", "01600026"],
    ["SRV11113", "CLI22223", "18951020"],
    ["SRV11114", "CLI22224", "32528969"],
  ])(`client ${clientSuite} Q=%s%s -> %s`, async (qs, qc, expected) => {
    const value = await generateOCRA({
      suite: clientSuite,
      secret: KEY64,
      question: [qs, qc],
      passwordHash: PIN_SHA1,
    });
    expect(value).toBe(expected);
  });
});

describe("RFC 6287 Appendix C.3 - plain signature", () => {
  const suite1 = "OCRA-1:HOTP-SHA256-8:QA08";
  it.each([
    ["SIG10000", "53095496"],
    ["SIG11000", "04110475"],
    ["SIG12000", "31331128"],
    ["SIG13000", "76028668"],
    ["SIG14000", "46554205"],
  ])(`${suite1} Q=%s -> %s`, async (question, expected) => {
    await expect(generateOCRA({ suite: suite1, secret: KEY32, question })).resolves.toBe(expected);
  });

  const suite2 = "OCRA-1:HOTP-SHA512-8:QA10-T1M";
  it.each([
    ["SIG1000000", "77537423"],
    ["SIG1100000", "31970405"],
    ["SIG1200000", "10235557"],
    ["SIG1300000", "95213541"],
    ["SIG1400000", "65360607"],
  ])(`${suite2} Q=%s T=132d0b6 -> %s`, async (question, expected) => {
    const value = await generateOCRA({
      suite: suite2,
      secret: KEY64,
      question,
      timestamp: T_132D0B6,
    });
    expect(value).toBe(expected);
  });
});

describe("test vector cross-checks", () => {
  it("computes the Appendix C PIN hash from the PIN itself", async () => {
    expect(hexEncode(await hashOCRAPassword("1234"))).toBe(PIN_SHA1);
  });

  it("derives Appendix C's T=132d0b6 from the timestamp", () => {
    expect(ocraTimeSteps("OCRA-1:HOTP-SHA512-8:QN08-T1M", T_132D0B6)).toBe(0x132d0b6n);
  });

  it("treats a joined challenge and its parts identically", async () => {
    const joined = await generateOCRA({
      suite: "OCRA-1:HOTP-SHA256-8:QA08",
      secret: KEY32,
      question: "CLI22220SRV11110",
    });
    expect(joined).toBe("28247970");
  });

  it("verifies every vector it generates", async () => {
    const suite = "OCRA-1:HOTP-SHA1-6:QN08";
    await expect(
      verifyOCRA({ suite, secret: KEY20, question: "00000000", response: "237653" }),
    ).resolves.toBe(true);
    await expect(
      verifyOCRA({ suite, secret: KEY20, question: "00000000", response: "243178" }),
    ).resolves.toBe(false);
  });

  it("resynchronizes a counter suite within the window", async () => {
    const suite = "OCRA-1:HOTP-SHA512-8:C-QN08";
    await expect(
      verifyOCRADelta({
        suite,
        secret: KEY64,
        counter: 0,
        question: "33333333",
        response: "25341727",
        counterWindow: 5,
      }),
    ).resolves.toEqual({ counter: 3, time: 0 });
  });

  it("accepts time drift within the window of a T suite", async () => {
    const suite = "OCRA-1:HOTP-SHA512-8:QN08-T1M";
    // The vector's own timestamp, checked from one minute later.
    await expect(
      verifyOCRADelta({
        suite,
        secret: KEY64,
        question: "00000000",
        response: "95209754",
        timestamp: T_132D0B6 + 60_000,
      }),
    ).resolves.toEqual({ counter: 0, time: -1 });

    await expect(
      verifyOCRA({
        suite,
        secret: KEY64,
        question: "00000000",
        response: "95209754",
        timestamp: T_132D0B6 + 60_000,
        timeWindow: 0,
      }),
    ).resolves.toBe(false);
  });
});
