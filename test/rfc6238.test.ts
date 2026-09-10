import { describe, expect, it } from "vitest";
import { generateTOTP, totpCounter, utf8Decode, verifyTOTP } from "../src/index.js";
import type { Algorithm } from "../src/index.js";

/**
 * RFC 6238 Appendix B, with the seeds from the RFC 6238 errata: the secret is
 * the ASCII digit run repeated to the block size of each hash.
 */
const SECRETS: Record<Algorithm, Uint8Array> = {
  "SHA-1": utf8Decode("12345678901234567890"),
  "SHA-256": utf8Decode("12345678901234567890123456789012"),
  "SHA-512": utf8Decode("1234567890123456789012345678901234567890123456789012345678901234"),
};

/** RFC 6238 Appendix B, Table 1. `time` is in seconds; codes are 8 digits. */
const VECTORS: Array<{ time: number; counterHex: string; algorithm: Algorithm; totp: string }> = [
  { time: 59, counterHex: "0000000000000001", algorithm: "SHA-1", totp: "94287082" },
  { time: 59, counterHex: "0000000000000001", algorithm: "SHA-256", totp: "46119246" },
  { time: 59, counterHex: "0000000000000001", algorithm: "SHA-512", totp: "90693936" },
  { time: 1111111109, counterHex: "00000000023523EC", algorithm: "SHA-1", totp: "07081804" },
  { time: 1111111109, counterHex: "00000000023523EC", algorithm: "SHA-256", totp: "68084774" },
  { time: 1111111109, counterHex: "00000000023523EC", algorithm: "SHA-512", totp: "25091201" },
  { time: 1111111111, counterHex: "00000000023523ED", algorithm: "SHA-1", totp: "14050471" },
  { time: 1111111111, counterHex: "00000000023523ED", algorithm: "SHA-256", totp: "67062674" },
  { time: 1111111111, counterHex: "00000000023523ED", algorithm: "SHA-512", totp: "99943326" },
  { time: 1234567890, counterHex: "000000000273EF07", algorithm: "SHA-1", totp: "89005924" },
  { time: 1234567890, counterHex: "000000000273EF07", algorithm: "SHA-256", totp: "91819424" },
  { time: 1234567890, counterHex: "000000000273EF07", algorithm: "SHA-512", totp: "93441116" },
  { time: 2000000000, counterHex: "0000000003F940AA", algorithm: "SHA-1", totp: "69279037" },
  { time: 2000000000, counterHex: "0000000003F940AA", algorithm: "SHA-256", totp: "90698825" },
  { time: 2000000000, counterHex: "0000000003F940AA", algorithm: "SHA-512", totp: "38618901" },
  { time: 20000000000, counterHex: "0000000027BC86AA", algorithm: "SHA-1", totp: "65353130" },
  { time: 20000000000, counterHex: "0000000027BC86AA", algorithm: "SHA-256", totp: "77737706" },
  { time: 20000000000, counterHex: "0000000027BC86AA", algorithm: "SHA-512", totp: "47863826" },
];

describe("RFC 6238 Appendix B test vectors", () => {
  it.each(VECTORS)("$algorithm at T=$time produces $totp", async ({ time, algorithm, totp }) => {
    const code = await generateTOTP({
      secret: SECRETS[algorithm],
      timestamp: time * 1000,
      digits: 8,
      algorithm,
    });
    expect(code).toBe(totp);
  });

  it.each(VECTORS)("$algorithm at T=$time uses counter 0x$counterHex", ({ time, counterHex }) => {
    expect(totpCounter({ timestamp: time * 1000 })).toBe(BigInt(`0x${counterHex}`));
  });

  it.each(VECTORS)("$algorithm at T=$time verifies its own code", async ({ time, algorithm, totp }) => {
    const accepted = await verifyTOTP({
      secret: SECRETS[algorithm],
      token: totp,
      timestamp: time * 1000,
      digits: 8,
      algorithm,
      window: 0,
    });
    expect(accepted).toBe(true);
  });

  it("accepts a Date as the timestamp", async () => {
    const code = await generateTOTP({
      secret: SECRETS["SHA-1"],
      timestamp: new Date(1234567890 * 1000),
      digits: 8,
    });
    expect(code).toBe("89005924");
  });

  it("accepts the SHA1 / SHA256 / SHA512 spellings used by otpauth URIs", async () => {
    await expect(
      generateTOTP({ secret: SECRETS["SHA-256"], timestamp: 59_000, digits: 8, algorithm: "SHA256" }),
    ).resolves.toBe("46119246");
    await expect(
      generateTOTP({ secret: SECRETS["SHA-512"], timestamp: 59_000, digits: 8, algorithm: "sha-512" }),
    ).resolves.toBe("90693936");
  });
});
