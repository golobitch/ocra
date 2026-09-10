import { afterEach, describe, expect, it, vi } from "vitest";
import { TOTPError, generateSecret, generateTOTP } from "../src/index.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("WebCrypto availability", () => {
  it("reports a clear error when the runtime has no crypto.subtle", async () => {
    vi.stubGlobal("crypto", { getRandomValues: globalThis.crypto.getRandomValues });

    const error = await generateTOTP({ secret: "JBSWY3DPEHPK3PXP" }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(TOTPError);
    expect((error as TOTPError).code).toBe("CRYPTO_UNAVAILABLE");
    expect((error as TOTPError).message).toMatch(/WebCrypto/);
  });

  it("reports the same error from generateSecret", () => {
    vi.stubGlobal("crypto", undefined);
    expect(() => generateSecret()).toThrow(/WebCrypto/);
  });
});
