import { webcrypto } from "node:crypto";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
}

if (!globalThis.CryptoKey) {
  const keyPair = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  );
  Object.defineProperty(globalThis, "CryptoKey", {
    value: keyPair.privateKey.constructor,
    configurable: true,
  });
}
