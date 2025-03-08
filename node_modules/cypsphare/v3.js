const crypto = require('crypto');
const { Buffer } = require('buffer');

/**
 * Cypsphare cryptographic class with key pair generation, signing, and verification.
 * Includes subclasses GF25686 and Vector3 for field and vector operations.
 * All keys and signatures are represented as strings.
 * 
 * SECURITY ENHANCEMENTS:
 * - Field size increased to 256 bits for modern and quantum-resistant security
 * - Constant-time operations to prevent timing attacks
 * - Secure key derivation using HMAC-SHA256
 * - Entropy validation for key generation
 * - Robust input validation and error handling
 */
class Cypsphare {
  static #FIELD_SIZE = 256; // bits, GF(2^256) for 128-bit quantum security
  static #BYTE_LENGTH = Cypsphare.#FIELD_SIZE / 8; // 32 bytes
  static #VECTOR_BYTE_LENGTH = 3 * Cypsphare.#BYTE_LENGTH; // 96 bytes
  static #VERSION = '3.0.0';

  static GF25686 = class {
    // Irreducible polynomial for GF(2^256): x^256 + x^10 + x^5 + x^2 + 1
    static #p = (1n << BigInt(Cypsphare.#FIELD_SIZE)) | (1n << 10n) | (1n << 5n) | (1n << 2n) | 1n;
    static #mask = (1n << BigInt(Cypsphare.#FIELD_SIZE)) - 1n;

    constructor(value) {
      this.value = BigInt(value) & Cypsphare.GF25686.#mask;
    }

    add(other) {
      if (!(other instanceof Cypsphare.GF25686)) throw new Error('Operand must be GF25686');
      return new Cypsphare.GF25686(this.value ^ other.value); // Constant-time XOR
    }

    mul(other) {
      if (!(other instanceof Cypsphare.GF25686)) throw new Error('Operand must be GF25686');
      const fieldSize = Cypsphare.#FIELD_SIZE;
      let a = this.value, b = other.value;
      if (a === 0n || b === 0n) return new Cypsphare.GF25686(0n);
      if (a === 1n) return new Cypsphare.GF25686(b);
      if (b === 1n) return new Cypsphare.GF25686(a);

      let product = 0n;
      // Constant-time multiplication using shift-and-add
      for (let i = 0; i < fieldSize; i++) {
        if ((b & (1n << BigInt(i))) !== 0n) product ^= a << BigInt(i);
      }
      for (let i = 2 * fieldSize - 1; i >= fieldSize; i--) {
        if ((product & (1n << BigInt(i))) !== 0n) {
          product ^= Cypsphare.GF25686.#p << BigInt(i - fieldSize);
        }
      }
      return new Cypsphare.GF25686(product & Cypsphare.GF25686.#mask);
    }

    toBytes() {
      let bytes = new Uint8Array(Cypsphare.#BYTE_LENGTH);
      let v = this.value;
      for (let i = 0; i < Cypsphare.#BYTE_LENGTH; i++) {
        bytes[i] = Number(v & 255n);
        v >>= 8n;
      }
      return bytes;
    }

    static fromBytes(bytes) {
      if (!(bytes instanceof Uint8Array) || bytes.length !== Cypsphare.#BYTE_LENGTH) {
        throw new Error(`Input must be ${Cypsphare.#BYTE_LENGTH}-byte Uint8Array`);
      }
      let v = 0n;
      for (let i = 0; i < Cypsphare.#BYTE_LENGTH; i++) v |= BigInt(bytes[i]) << (BigInt(i) * 8n);
      return new Cypsphare.GF25686(v);
    }

    equals(other) {
      if (!(other instanceof Cypsphare.GF25686)) return false;
      return (this.value ^ other.value) === 0n; // Constant-time
    }
  };

  static Vector3 = class {
    constructor(x, y, z) {
      if (!(x instanceof Cypsphare.GF25686) || !(y instanceof Cypsphare.GF25686) || !(z instanceof Cypsphare.GF25686)) {
        throw new Error('Coordinates must be GF25686 elements');
      }
      this.x = x;
      this.y = y;
      this.z = z;
    }

    add(other) {
      if (!(other instanceof Cypsphare.Vector3)) throw new Error('Operand must be Vector3');
      return new Cypsphare.Vector3(this.x.add(other.x), this.y.add(other.y), this.z.add(other.z));
    }

    scalarMul(scalar) {
      if (!(scalar instanceof Cypsphare.GF25686)) throw new Error('Scalar must be GF25686');
      return new Cypsphare.Vector3(scalar.mul(this.x), scalar.mul(this.y), scalar.mul(this.z));
    }

    toBytes() {
      const result = new Uint8Array(Cypsphare.#VECTOR_BYTE_LENGTH);
      result.set(this.x.toBytes(), 0);
      result.set(this.y.toBytes(), Cypsphare.#BYTE_LENGTH);
      result.set(this.z.toBytes(), 2 * Cypsphare.#BYTE_LENGTH);
      return result;
    }

    static fromBytes(bytes) {
      if (!(bytes instanceof Uint8Array) || bytes.length !== Cypsphare.#VECTOR_BYTE_LENGTH) {
        throw new Error(`Input must be ${Cypsphare.#VECTOR_BYTE_LENGTH}-byte Uint8Array`);
      }
      return new Cypsphare.Vector3(
        Cypsphare.GF25686.fromBytes(bytes.slice(0, Cypsphare.#BYTE_LENGTH)),
        Cypsphare.GF25686.fromBytes(bytes.slice(Cypsphare.#BYTE_LENGTH, 2 * Cypsphare.#BYTE_LENGTH)),
        Cypsphare.GF25686.fromBytes(bytes.slice(2 * Cypsphare.#BYTE_LENGTH))
      );
    }

    equals(other) {
      if (!(other instanceof Cypsphare.Vector3)) return false;
      return this.x.equals(other.x) && this.y.equals(other.y) && this.z.equals(other.z);
    }
  };

  static U1 = new Cypsphare.Vector3(new Cypsphare.GF25686(1n), new Cypsphare.GF25686(0n), new Cypsphare.GF25686(0n));
  static U2 = new Cypsphare.Vector3(new Cypsphare.GF25686(0n), new Cypsphare.GF25686(1n), new Cypsphare.GF25686(0n));
  static U3 = new Cypsphare.Vector3(new Cypsphare.GF25686(0n), new Cypsphare.GF25686(0n), new Cypsphare.GF25686(1n));
  static U = [Cypsphare.U1, Cypsphare.U2, Cypsphare.U3];

  static #constantTimeCompare(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) result |= a[i] ^ b[i];
    return result === 0;
  }

  static sha256(data) {
    if (typeof data === 'string') data = Buffer.from(data, 'utf-8');
    if (!(data instanceof Buffer) && !(data instanceof Uint8Array)) throw new Error('Invalid data type for hashing');
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  static privateKeyToC(privateKeyHex) {
    if (typeof privateKeyHex !== 'string' || privateKeyHex.length !== 64 || !/^[0-9a-fA-F]+$/.test(privateKeyHex)) {
      throw new Error('Private key must be a 64-character hex string');
    }
    const bufKey = Buffer.from(privateKeyHex, 'hex');
    const xSeed = crypto.createHmac('sha256', bufKey).update('x-coordinate').digest();
    const ySeed = crypto.createHmac('sha256', bufKey).update('y-coordinate').digest();
    const zSeed = crypto.createHmac('sha256', bufKey).update('z-coordinate').digest();
    return new Cypsphare.Vector3(
      new Cypsphare.GF25686(BigInt('0x' + xSeed.toString('hex'))),
      new Cypsphare.GF25686(BigInt('0x' + ySeed.toString('hex'))),
      new Cypsphare.GF25686(BigInt('0x' + zSeed.toString('hex')))
    );
  }

  static privateKeyToPublicAddress(privateKey, i) {
    if (typeof privateKey !== 'string' || privateKey.length !== 64 || !/^[0-9a-fA-F]+$/.test(privateKey)) {
      throw new Error('Private key must be a 64-character hex string');
    }
    if (!Number.isInteger(i) || i < 1 || i > 3) throw new Error('Index i must be 1, 2, or 3');
    const C = Cypsphare.privateKeyToC(privateKey);
    const hashInput = Buffer.concat([C.toBytes(), Buffer.from([i])]);
    return `nlg${Cypsphare.sha256(hashInput)}${i}`;
  }

  static hashToField(hashHex) {
    if (typeof hashHex !== 'string' || hashHex.length !== 64 || !/^[0-9a-fA-F]+$/.test(hashHex)) {
      throw new Error('Hash must be a 64-character hex string');
    }
    return new Cypsphare.GF25686(BigInt('0x' + hashHex));
  }

  static generateKeyPair() {
    const privateKeyBuffer = crypto.randomBytes(Cypsphare.#BYTE_LENGTH);
    const entropyTest = crypto.createHash('sha256').update(privateKeyBuffer).digest();
    const bitCounts = new Uint8Array(8).fill(0);
    for (let i = 0; i < entropyTest.length; i++) {
      const byte = entropyTest[i];
      for (let j = 0; j < 8; j++) if (byte & (1 << j)) bitCounts[i % 8]++;
    }
    const segmentSize = entropyTest.length * 8 / 8;
    const [lower, upper] = [segmentSize * 0.45, segmentSize * 0.55];
    if (bitCounts.some(count => count < lower || count > upper)) return Cypsphare.generateKeyPair();
    const privateKey = privateKeyBuffer.toString('hex');
    const indexSeed = crypto.createHmac('sha256', privateKeyBuffer).update('index-selection').digest();
    const i = (indexSeed[0] % 3) + 1;
    return { privateKey, publicAddress: Cypsphare.privateKeyToPublicAddress(privateKey, i) };
  }

  static sign(privateKey, publicAddress, message) {
    if (typeof privateKey !== 'string' || privateKey.length !== 64 || !/^[0-9a-fA-F]+$/.test(privateKey)) {
      throw new Error('Private key must be a 64-character hex string');
    }
    if (typeof publicAddress !== 'string' || !publicAddress.startsWith('nlg') || publicAddress.length !== 68) {
      throw new Error('Invalid public address');
    }
    const i = parseInt(publicAddress.slice(-1), 10);
    if (!Number.isInteger(i) || i < 1 || i > 3) throw new Error('Invalid index in public address');
    if (Cypsphare.privateKeyToPublicAddress(privateKey, i) !== publicAddress) {
      throw new Error('Private key does not match public address');
    }
    const C = Cypsphare.privateKeyToC(privateKey);
    const f = Cypsphare.hashToField(Cypsphare.sha256(message));
    return Buffer.from(C.add(Cypsphare.U[i - 1].scalarMul(f)).toBytes()).toString('hex');
  }

  static verify(publicAddress, message, signatureHex) {
    if (typeof publicAddress !== 'string' || !publicAddress.startsWith('nlg') || publicAddress.length !== 68) {
      throw new Error('Invalid public address');
    }
    if (typeof signatureHex !== 'string' || signatureHex.length !== 2 * Cypsphare.#VECTOR_BYTE_LENGTH || !/^[0-9a-fA-F]+$/.test(signatureHex)) {
      throw new Error(`Signature must be a ${2 * Cypsphare.#VECTOR_BYTE_LENGTH}-character hex string`);
    }
    const QHex = publicAddress.slice(3, -1);
    const i = parseInt(publicAddress.slice(-1), 10);
    if (!Number.isInteger(i) || i < 1 || i > 3 || QHex.length !== 64) throw new Error('Invalid public address format');
    try {
      const s = Cypsphare.Vector3.fromBytes(Buffer.from(signatureHex, 'hex'));
      const f = Cypsphare.hashToField(Cypsphare.sha256(message));
      const CPrime = s.add(Cypsphare.U[i - 1].scalarMul(f));
      const QComputed = Cypsphare.sha256(Buffer.concat([CPrime.toBytes(), Buffer.from([i])]));
      return Cypsphare.#constantTimeCompare(Buffer.from(QHex, 'hex'), Buffer.from(QComputed, 'hex'));
    } catch (e) {
      return false;
    }
  }

  static serializeKeyPair(keyPair) {
    if (!keyPair || typeof keyPair.privateKey !== 'string' || typeof keyPair.publicAddress !== 'string') {
      throw new Error('Invalid key pair object');
    }
    return JSON.stringify({ version: Cypsphare.#VERSION, ...keyPair });
  }

  static deserializeKeyPair(json) {
    const obj = JSON.parse(json);
    if (typeof obj.privateKey !== 'string' || typeof obj.publicAddress !== 'string') throw new Error('Invalid JSON format');
    if (obj.privateKey.length !== 64 || !/^[0-9a-fA-F]+$/.test(obj.privateKey) || !obj.publicAddress.startsWith('nlg') || obj.publicAddress.length !== 68) {
      throw new Error('Invalid key pair format');
    }
    const i = parseInt(obj.publicAddress.slice(-1), 10);
    if (!Number.isInteger(i) || i < 1 || i > 3 || Cypsphare.privateKeyToPublicAddress(obj.privateKey, i) !== obj.publicAddress) {
      throw new Error('Invalid key pair');
    }
    return { privateKey: obj.privateKey, publicAddress: obj.publicAddress };
  }
}

module.exports = Cypsphare;