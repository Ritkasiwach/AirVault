// 100% Native Browser Web Crypto API (AES-256-GCM + PBKDF2)

const enc = new TextEncoder();

// 1. Room Code se 256-bit AES-GCM Key derive karna
export async function deriveRoomKey(roomCode: string): Promise<CryptoKey> {
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(roomCode.toUpperCase()),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode("airvault-zero-trust-salt-v1"),
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// 2. 64KB Chunk ko AES-256-GCM se Encrypt karna
export async function encryptChunk(
  key: CryptoKey,
  plainBuffer: ArrayBuffer
): Promise<{ iv: Uint8Array; cipherBuffer: ArrayBuffer }> {
  // Har chunk ke liye fresh 12-byte random IV
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const cipherBuffer = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plainBuffer
  );
  return { iv, cipherBuffer };
}

// 3. Encrypted Chunk ko wapas Decrypt karna
export async function decryptChunk(
  key: CryptoKey,
  ivInput: Uint8Array | ArrayBuffer,
  cipherBuffer: ArrayBuffer
): Promise<ArrayBuffer> {
  const iv = ivInput instanceof Uint8Array ? ivInput : new Uint8Array(ivInput);
  return window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    cipherBuffer
  );
}