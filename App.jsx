import React, { useState } from "react";

// Generate a random big integer
function randomBigInt(bits = 128) {
  const array = new Uint8Array(bits / 8);
  crypto.getRandomValues(array);
  return BigInt(
    "0x" + [...array].map((x) => x.toString(16).padStart(2, "0")).join("")
  );
}

// Fast modular exponentiation
function modPow(base, exponent, modulus) {
  if (modulus === 1n) return 0n;
  let result = 1n;
  base = base % modulus;
  while (exponent > 0) {
    if (exponent % 2n === 1n) {
      result = (result * base) % modulus;
    }
    exponent = exponent >> 1n;
    base = (base * base) % modulus;
  }
  return result;
}

// Derive shared secret key
function deriveSharedKey(privateKeys, publicKeys, prime, generator) {
  let secret = 1n;
  for (let i = 0; i < privateKeys.length; i++) {
    secret = modPow(publicKeys[i], privateKeys[i], prime);
  }
  return secret;
}

// Generate a proper AES-GCM key from shared secret
async function getAESKey(sharedSecret) {
  const enc = new TextEncoder();
  const hash = await crypto.subtle.digest(
    "SHA-256",
    enc.encode(sharedSecret.toString())
  );
  return crypto.subtle.importKey("raw", hash, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export default function App() {
  const [prime] = useState(0xffffffffffc5n);
  const [generator] = useState(5n);
  const [numParties, setNumParties] = useState(2);
  const [privateKeys, setPrivateKeys] = useState([]);
  const [publicKeys, setPublicKeys] = useState([]);
  const [sharedSecret, setSharedSecret] = useState(null);
  const [plainText, setPlainText] = useState("");
  const [cipherText, setCipherText] = useState("");
  const [decryptedText, setDecryptedText] = useState("");

  // Generate keys
  const generateKeys = () => {
    let priv = [];
    let pub = [];
    for (let i = 0; i < numParties; i++) {
      let pk = randomBigInt(64);
      priv.push(pk);
      pub.push(modPow(generator, pk, prime));
    }
    setPrivateKeys(priv);
    setPublicKeys(pub);
    setSharedSecret(null);
    setCipherText("");
    setDecryptedText("");
  };

  // Compute shared secret
  const computeShared = () => {
    const secret = deriveSharedKey(privateKeys, publicKeys, prime, generator);
    setSharedSecret(secret);
    setCipherText("");
    setDecryptedText("");
  };

  // Encrypt plaintext
  const encryptText = async () => {
    if (!sharedSecret) return alert("Generate keys and shared secret first!");
    try {
      const key = await getAESKey(sharedSecret);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(plainText);
      const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
      setCipherText(JSON.stringify({ data: Array.from(new Uint8Array(encrypted)), iv: Array.from(iv) }));
      setDecryptedText("");
    } catch (e) {
      alert("Encryption failed: " + e.message);
    }
  };

  // Decrypt ciphertext
  const decryptText = async () => {
    if (!cipherText) return alert("No ciphertext to decrypt!");
    try {
      const parsed = JSON.parse(cipherText);
      const key = await getAESKey(sharedSecret);
      const iv = new Uint8Array(parsed.iv);
      const data = new Uint8Array(parsed.data);
      const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
      setDecryptedText(new TextDecoder().decode(decrypted));
    } catch (e) {
      alert("Decryption failed: Wrong key or corrupted data");
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-900 to-gray-900 text-white p-6 flex flex-col items-center">
      
      {/* Header */}
      <header className="mb-8 text-center">
        <h1 className="text-4xl font-bold mb-2">🔐 Multi Diffie-Hellman Encryption</h1>
        <p className="text-gray-300">Securely exchange secrets & encrypt your messages</p>
      </header>

      {/* Key Generation Section */}
      <section className="bg-gray-800 rounded-2xl shadow-lg p-6 w-full max-w-2xl mb-6">
        <h2 className="text-2xl font-semibold mb-4">1️⃣ Key Generation</h2>
        
        <div className="flex items-center gap-4 mb-4">
          <label>
            Parties:
            <input
              type="number"
              min="2"
              max="10"
              value={numParties}
              onChange={(e) => setNumParties(Number(e.target.value))}
              className="ml-2 px-2 py-1 rounded bg-gray-700 text-white w-20"
            />
          </label>
          <button
            onClick={generateKeys}
            className="bg-purple-600 px-4 py-2 rounded hover:bg-purple-500 transition"
          >
            Generate Keys
          </button>
          <button
            onClick={computeShared}
            className="bg-blue-600 px-4 py-2 rounded hover:bg-blue-500 transition"
          >
            Compute Shared Secret
          </button>
        </div>

        {sharedSecret && (
          <div className="bg-gray-700 p-3 rounded break-words text-green-400">
            Shared Secret: {sharedSecret.toString()}
          </div>
        )}
      </section>

      {/* Encryption / Decryption Section */}
      <section className="bg-gray-800 rounded-2xl shadow-lg p-6 w-full max-w-2xl mb-6">
        <h2 className="text-2xl font-semibold mb-4">2️⃣ Encrypt / Decrypt Messages</h2>
        
        <textarea
          placeholder="Enter plaintext message"
          value={plainText}
          onChange={(e) => setPlainText(e.target.value)}
          className="w-full h-24 p-2 rounded bg-gray-700 mb-4 resize-none"
        />

        <div className="flex gap-4 mb-4">
          <button
            onClick={encryptText}
            className="bg-green-600 px-4 py-2 rounded hover:bg-green-500 transition"
          >
            Encrypt
          </button>
          <button
            onClick={decryptText}
            className="bg-red-600 px-4 py-2 rounded hover:bg-red-500 transition"
          >
            Decrypt
          </button>
        </div>

        {cipherText && (
          <div className="bg-gray-700 p-3 rounded break-words text-yellow-400 mb-2">
            Ciphertext: {cipherText}
          </div>
        )}
        {decryptedText && (
          <div className="bg-gray-700 p-3 rounded break-words text-green-400">
            Decrypted: {decryptedText}
          </div>
        )}
      </section>

      {/* Instructions Section */}
      <section className="bg-gray-800 rounded-2xl shadow-lg p-6 w-full max-w-2xl text-gray-300">
        <h2 className="text-2xl font-semibold mb-2">💡 Instructions</h2>
        <ul className="list-disc ml-5">
          <li>Set number of parties and generate keys.</li>
          <li>Compute shared secret after generating keys.</li>
          <li>Type your message, then encrypt it.</li>
          <li>Use the ciphertext and decrypt it to get the original message.</li>
        </ul>
      </section>
    </div>
  );
}
