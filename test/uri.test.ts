import { describe, expect, it } from "vitest";
import {
  TOTPError,
  createOTPAuthURI,
  generateTOTP,
  parseOTPAuthURI,
  utf8Decode,
} from "../src/index.js";

const SECRET = "JBSWY3DPEHPK3PXP";

describe("createOTPAuthURI", () => {
  it("builds the Key Uri Format URI", () => {
    const uri = createOTPAuthURI({ secret: SECRET, account: "alice@example.com", issuer: "ACME Co" });
    expect(uri).toBe(
      "otpauth://totp/ACME%20Co:alice%40example.com" +
        "?secret=JBSWY3DPEHPK3PXP&issuer=ACME+Co&algorithm=SHA1&digits=6&period=30",
    );
  });

  it("omits the label prefix when there is no issuer", () => {
    const uri = createOTPAuthURI({ secret: SECRET, account: "alice@example.com" });
    expect(uri.startsWith("otpauth://totp/alice%40example.com?")).toBe(true);
    expect(uri).not.toContain("issuer=");
  });

  it("writes algorithm names in the spelling the format uses", () => {
    expect(createOTPAuthURI({ secret: SECRET, account: "a", algorithm: "SHA-256" })).toContain(
      "algorithm=SHA256",
    );
  });

  it("encodes raw byte secrets as base32", () => {
    const uri = createOTPAuthURI({ secret: utf8Decode("Hello!"), account: "a" });
    expect(uri).toContain("secret=JBSWY3DPEE");
  });

  it("normalizes a spaced or lowercase secret", () => {
    const uri = createOTPAuthURI({ secret: "jbswy3dp ehpk3pxp", account: "a" });
    expect(uri).toContain(`secret=${SECRET}`);
  });

  it("percent-encodes label characters that break naive parsers", () => {
    const uri = createOTPAuthURI({ secret: SECRET, account: "a b/c?d#e", issuer: "Foo&Bar" });
    expect(uri).toContain("otpauth://totp/Foo%26Bar:a%20b%2Fc%3Fd%23e?");
  });

  it("rejects an issuer containing a colon, which would corrupt the label", () => {
    expect(() => createOTPAuthURI({ secret: SECRET, account: "a", issuer: "AC:ME" })).toThrow(
      TOTPError,
    );
  });

  it("rejects an empty account", () => {
    expect(() => createOTPAuthURI({ secret: SECRET, account: "" })).toThrow(/account/);
  });

  it("rejects an invalid secret", () => {
    expect(() => createOTPAuthURI({ secret: "not base32!", account: "a" })).toThrow(TOTPError);
  });
});

describe("parseOTPAuthURI", () => {
  it("round-trips a URI it created", () => {
    const options = {
      secret: SECRET,
      account: "alice@example.com",
      issuer: "ACME Co",
      digits: 8,
      period: 60,
      algorithm: "SHA-512",
    } as const;
    expect(parseOTPAuthURI(createOTPAuthURI(options))).toEqual({
      secret: SECRET,
      account: "alice@example.com",
      issuer: "ACME Co",
      digits: 8,
      period: 60,
      algorithm: "SHA-512",
    });
  });

  it("applies the spec defaults for omitted parameters", () => {
    expect(parseOTPAuthURI(`otpauth://totp/alice?secret=${SECRET}`)).toEqual({
      secret: SECRET,
      account: "alice",
      digits: 6,
      period: 30,
      algorithm: "SHA-1",
    });
  });

  it("splits an issuer-prefixed label", () => {
    const parsed = parseOTPAuthURI(`otpauth://totp/ACME%20Co:alice?secret=${SECRET}`);
    expect(parsed.issuer).toBe("ACME Co");
    expect(parsed.account).toBe("alice");
  });

  it("strips the optional space after the label separator", () => {
    expect(parseOTPAuthURI(`otpauth://totp/ACME:%20alice?secret=${SECRET}`).account).toBe("alice");
  });

  it("prefers the issuer parameter over the label prefix", () => {
    const parsed = parseOTPAuthURI(`otpauth://totp/Stale:alice?secret=${SECRET}&issuer=Current`);
    expect(parsed.issuer).toBe("Current");
    expect(parsed.account).toBe("alice");
  });

  it("keeps a colon that appears later in the account", () => {
    const parsed = parseOTPAuthURI(`otpauth://totp/ACME:a:b?secret=${SECRET}`);
    expect(parsed.issuer).toBe("ACME");
    expect(parsed.account).toBe("a:b");
  });

  it("accepts an uppercase type", () => {
    expect(parseOTPAuthURI(`otpauth://TOTP/alice?secret=${SECRET}`).account).toBe("alice");
  });

  it("rejects hotp URIs, other schemes and malformed input", () => {
    expect(() => parseOTPAuthURI(`otpauth://hotp/alice?secret=${SECRET}&counter=0`)).toThrow(/totp/i);
    expect(() => parseOTPAuthURI(`https://example.com/?secret=${SECRET}`)).toThrow(/otpauth/i);
    expect(() => parseOTPAuthURI("not a uri")).toThrow(/valid URI/i);
  });

  it("rejects a label that is not valid percent-encoding", () => {
    expect(() => parseOTPAuthURI(`otpauth://totp/%E0%A4%A?secret=${SECRET}`)).toThrow(
      /percent-encoding/,
    );
  });

  it("rejects a URI without a secret", () => {
    expect(() => parseOTPAuthURI("otpauth://totp/alice")).toThrow(/secret/);
  });

  it("rejects out-of-range parameters", () => {
    expect(() => parseOTPAuthURI(`otpauth://totp/a?secret=${SECRET}&period=0`)).toThrow(/period/);
    expect(() => parseOTPAuthURI(`otpauth://totp/a?secret=${SECRET}&digits=abc`)).toThrow(/digits/);
    expect(() => parseOTPAuthURI(`otpauth://totp/a?secret=${SECRET}&digits=99`)).toThrow(TOTPError);
    expect(() => parseOTPAuthURI(`otpauth://totp/a?secret=${SECRET}&algorithm=MD5`)).toThrow(
      /Unsupported algorithm/,
    );
  });

  it("produces parameters that generate the original code", async () => {
    const uri = createOTPAuthURI({ secret: SECRET, account: "alice", digits: 8, algorithm: "SHA-256" });
    const parsed = parseOTPAuthURI(uri);
    const fromParsed = await generateTOTP({ ...parsed, timestamp: 59_000 });
    const direct = await generateTOTP({
      secret: SECRET,
      digits: 8,
      algorithm: "SHA-256",
      timestamp: 59_000,
    });
    expect(fromParsed).toBe(direct);
  });
});
