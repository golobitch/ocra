import { describe, expect, it } from "vitest";
import {
  TOTPError,
  base32Decode,
  base32Encode,
  hexDecode,
  hexEncode,
  utf8Decode,
} from "../src/index.js";

/** RFC 4648 §10 base32 test vectors. */
const RFC4648 = [
  ["", ""],
  ["f", "MY"],
  ["fo", "MZXQ"],
  ["foo", "MZXW6"],
  ["foob", "MZXW6YQ"],
  ["fooba", "MZXW6YTB"],
  ["foobar", "MZXW6YTBOI"],
] as const;

describe("base32", () => {
  it.each(RFC4648.filter(([input]) => input !== ""))(
    "decodes %s from its RFC 4648 encoding",
    (plain, encoded) => {
      expect(new TextDecoder().decode(base32Decode(encoded))).toBe(plain);
    },
  );

  it.each(RFC4648)("encodes %s as %s (unpadded)", (plain, encoded) => {
    expect(base32Encode(utf8Decode(plain))).toBe(encoded);
  });

  it("round-trips arbitrary bytes", () => {
    for (let length = 1; length <= 64; length++) {
      const bytes = Uint8Array.from({ length }, (_, i) => (i * 37 + length) % 256);
      expect(base32Decode(base32Encode(bytes))).toEqual(bytes);
    }
  });

  it("accepts the padding, spacing and casing that apps display", () => {
    const expected = base32Decode("MZXW6YTBOI");
    for (const variant of ["mzxw6ytboi", "MZXW 6YTB OI", "MZXW-6YTB-OI", "MZXW6YTBOI======"]) {
      expect(base32Decode(variant)).toEqual(expected);
    }
  });

  it("rejects characters outside the alphabet", () => {
    for (const invalid of ["MZXW6YTB01", "MZXW6YTB!I", "MZXW6YTB8I"]) {
      expect(() => base32Decode(invalid)).toThrow(TOTPError);
    }
  });

  it("rejects an empty secret", () => {
    expect(() => base32Decode("")).toThrow(/empty/i);
    expect(() => base32Decode("======")).toThrow(/empty/i);
  });

  it("rejects lengths that end mid-byte", () => {
    // 1, 3 and 6 characters cannot terminate a valid base32 encoding.
    for (const invalid of ["M", "MZX", "MZXW6Y"]) {
      expect(() => base32Decode(invalid)).toThrow(/partial byte/i);
    }
  });

  it("rejects trailing bits that are not zero padding", () => {
    // "MZXW6YTBOJ" carries a set bit past the last whole byte; "…OI" does not.
    expect(() => base32Decode("MZXW6YTBOJ")).toThrow(/partial byte/i);
    expect(() => base32Decode("MZXW6YTBOI")).not.toThrow();
  });

  it("reports the offending character and its index", () => {
    expect(() => base32Decode("MZXW6YTB0I")).toThrow(/"0" at index 8/);
  });
});

describe("hex", () => {
  it("round-trips bytes", () => {
    const bytes = new Uint8Array([0x00, 0x0f, 0x7f, 0x80, 0xff]);
    expect(hexEncode(bytes)).toBe("000f7f80ff");
    expect(hexDecode("000f7f80ff")).toEqual(bytes);
  });

  it("accepts uppercase and internal whitespace", () => {
    expect(hexDecode("DE AD BE EF")).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  it("rejects odd lengths, empty input and non-hex characters", () => {
    for (const invalid of ["abc", "", "  ", "zz"]) {
      expect(() => hexDecode(invalid)).toThrow(TOTPError);
    }
  });
});

describe("utf8Decode", () => {
  it("encodes multi-byte characters", () => {
    expect(utf8Decode("é")).toEqual(new Uint8Array([0xc3, 0xa9]));
  });
});
