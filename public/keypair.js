/**
 * Public / Private Key Demo — JavaScript (Node.js)
 * Blockchain 101 context: secp256k1 + ECDSA + SHA-256
 *
 * Install:  npm install elliptic
 * Run:      node keypair.js
 */

'use strict';

const { createHash } = require('crypto');
const EC = require('elliptic').ec;

const ec = new EC('secp256k1');

// ─── 1. Key Generation ───────────────────────────────────────────────────────
function generateKeyPair() {
  const keyPair = ec.genKeyPair();
  return {
    privateKey: keyPair.getPrivate('hex'),
    publicKey:  keyPair.getPublic('hex'),   // uncompressed 65-byte, prefix 04
    _kp: keyPair                            // raw keypair (for signing)
  };
}

// ─── 2. Hash ─────────────────────────────────────────────────────────────────
function hashMessage(message) {
  return createHash('sha256').update(message).digest('hex');
}

// ─── 3. Sign ─────────────────────────────────────────────────────────────────
function signMessage(privateKeyHex, message) {
  const key  = ec.keyFromPrivate(privateKeyHex, 'hex');
  const hash = hashMessage(message);
  const sig  = key.sign(hash);
  return {
    r:   sig.r.toString(16).padStart(64, '0'),
    s:   sig.s.toString(16).padStart(64, '0'),
    der: sig.toDER('hex')
  };
}

// ─── 4. Verify ───────────────────────────────────────────────────────────────
function verifySignature(publicKeyHex, message, signature) {
  const key  = ec.keyFromPublic(publicKeyHex, 'hex');
  const hash = hashMessage(message);
  return key.verify(hash, { r: signature.r, s: signature.s });
}

// ─── 5. Key Database (in-memory + JSON serializable) ─────────────────────────
class KeyDatabase {
  constructor() {
    this.records = [];
  }

  add(label, keyPair) {
    const record = {
      id:         crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2),
      label,
      publicKey:  keyPair.publicKey,
      privateKey: keyPair.privateKey,  // ⚠ keep secret in production
      curve:      'secp256k1',
      createdAt:  new Date().toISOString()
    };
    this.records.push(record);
    return record;
  }

  findById(id) {
    return this.records.find(r => r.id === id) || null;
  }

  findByLabel(label) {
    return this.records.filter(r => r.label === label);
  }

  toJSON() {
    return JSON.stringify({ version: 1, keys: this.records }, null, 2);
  }
}

// ─── 6. Signed Transaction ────────────────────────────────────────────────────
function createSignedTransaction(privateKeyHex, publicKeyHex, txData) {
  const payload = JSON.stringify(txData);
  const hash    = hashMessage(payload);
  const sig     = signMessage(privateKeyHex, payload);
  return {
    transaction: txData,
    hash,
    signature: { algorithm: 'ECDSA-secp256k1', ...sig },
    publicKey: publicKeyHex,
    verified: verifySignature(publicKeyHex, payload, sig)
  };
}

// ─── Demo ─────────────────────────────────────────────────────────────────────
(function demo() {
  console.log('=== Public/Private Key Demo ===\n');

  // Generate
  const { privateKey, publicKey } = generateKeyPair();
  console.log('Private key:', privateKey);
  console.log('Public key :', publicKey.slice(0, 40) + '...\n');

  // Sign
  const message = 'Send 1 BTC to Alice';
  const sig     = signMessage(privateKey, message);
  console.log('Message    :', message);
  console.log('Hash       :', hashMessage(message));
  console.log('Sig r      :', sig.r);
  console.log('Sig s      :', sig.s);

  // Verify original
  const valid = verifySignature(publicKey, message, sig);
  console.log('\nValid (original) :', valid);  // true

  // Verify tampered
  const tampered = verifySignature(publicKey, message + '!', sig);
  console.log('Valid (tampered)  :', tampered); // false

  // Database
  const db = new KeyDatabase();
  db.add('Alice wallet', { privateKey, publicKey });
  console.log('\nDatabase JSON:\n', db.toJSON());

  // Signed transaction
  const tx = createSignedTransaction(privateKey, publicKey, {
    from:   publicKey.slice(0, 12) + '...',
    to:     '1A1zP1eP5QG...',
    amount: 1.0,
    asset:  'BTC'
  });
  console.log('\nSigned transaction verified:', tx.verified);
})();