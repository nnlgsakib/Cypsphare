# Cypsphare

A quantum-resistant cryptographic library utilizing finite field operations in GF(2^256) with vector-based signatures.

## Overview

Cypsphare is a modern cryptographic library that provides key pair generation, digital signatures, and verification in a quantum-resistant framework. It uses a novel approach based on finite field math and 3D vector operations to create a secure digital signature scheme.

## Features

- **Quantum-Resistant Security**: Uses 256-bit field sizes (GF(2^256)) for post-quantum security
- **Vector-Based Signatures**: Employs 3D vector operations in finite fields
- **Constant-Time Operations**: Protects against timing attacks
- **Secure Key Derivation**: Implements HMAC-SHA256 for key derivation
- **Entropy Validation**: Ensures high-quality randomness for key generation
- **Comprehensive Error Handling**: Robust input validation throughout

## Mathematical Foundation

### Finite Field Operations

The library implements the Galois Field GF(2^256) with operations:

- **Addition**: Implemented as bitwise XOR
  ```
  a + b = a ⊕ b
  ```

- **Multiplication**: Polynomial multiplication modulo an irreducible polynomial
  ```
  p(x) = x^256 + x^10 + x^5 + x^2 + 1
  ```
  The multiplication algorithm uses a shift-and-add approach with reduction by the irreducible polynomial.

### Vector Operations

Cypsphare uses 3D vectors over GF(2^256) with operations:

- **Vector Addition**: 
  ```
  (x₁, y₁, z₁) + (x₂, y₂, z₂) = (x₁+x₂, y₁+y₂, z₁+z₂)
  ```

- **Scalar Multiplication**:
  ```
  s · (x, y, z) = (s·x, s·y, s·z)
  ```

### Signature Scheme

The signature scheme works as follows:

1. **Key Generation**:
   - Generate a random 256-bit private key
   - Derive a vector C from the private key using HMAC-SHA256
   - Select a basis vector Uᵢ (i ∈ {1,2,3})
   - Public address = "nlg" + SHA256(C || i) + i

2. **Signing**:
   - For message m, compute f = SHA256(m) interpreted as a field element
   - Signature s = C + f·Uᵢ

3. **Verification**:
   - Parse public address to extract Q and i
   - Compute f = SHA256(m) interpreted as a field element
   - Compute C' = s - f·Uᵢ
   - Verify Q = SHA256(C' || i)

## Comparison with ECC (Elliptic Curve Cryptography)

Cypsphare can serve as an alternative to ECC with these key differences:

| Feature | Cypsphare | ECC |
|---------|-----------|-----|
| Mathematical Structure | Vectors over GF(2^256) | Points on elliptic curves |
| Operations | Vector addition, scalar multiplication | Point addition, scalar multiplication |
| Quantum Resistance | Strong (256-bit field size) | Vulnerable to Shor's algorithm |
| Signature Size | 96 bytes (fixed) | Variable (typically 64-72 bytes) |
| Computational Efficiency | Linear operations | More complex curve operations |

## Quantum Security

Cypsphare is designed to be resistant to quantum computing attacks:

1. **Shor's Algorithm Resistance**: Unlike ECC and RSA which are vulnerable to Shor's algorithm, Cypsphare's approach doesn't rely on the discrete logarithm or integer factorization problems.

2. **Large Field Size**: The 256-bit field size provides approximately 128 bits of quantum security, as quantum algorithms like Grover's would require O(2^128) operations.

3. **Vector-Based Approach**: The multi-dimensional vector operations add additional complexity against quantum attacks.

## Installation

```bash
npm install cypsphare
```

## Requirements

- Node.js v12+
- crypto and buffer modules

## Advanced Usage Guide

### Basic Key Management

```javascript
const Cypsphare = require('cypsphare');

// Generate a new key pair
const keyPair = Cypsphare.generateKeyPair();
const { privateKey, publicAddress } = keyPair;

// Save keys to JSON file
const fs = require('fs');
const serialized = Cypsphare.serializeKeyPair(keyPair);
fs.writeFileSync('keystore.json', serialized);

// Load keys from JSON file
const loadedJson = fs.readFileSync('keystore.json', 'utf8');
const loadedKeyPair = Cypsphare.deserializeKeyPair(loadedJson);
```

### Message Signing and Verification

```javascript
const Cypsphare = require('cypsphare');

// Load or generate keys
const keyPair = Cypsphare.generateKeyPair();
const { privateKey, publicAddress } = keyPair;

// Sign a message
const message = 'This is a secure message';
const signature = Cypsphare.sign(privateKey, publicAddress, message);

// Verify the signature
const isValid = Cypsphare.verify(publicAddress, message, signature);
console.log(`Signature verification result: ${isValid}`);

// Tampered message verification will fail
const tamperedMessage = 'This is a tampered message';
const isInvalid = Cypsphare.verify(publicAddress, tamperedMessage, signature);
console.log(`Tampered verification result: ${isInvalid}`); // Will be false
```

### Secure Document Signing

```javascript
const Cypsphare = require('cypsphare');
const fs = require('fs');
const crypto = require('crypto');

// Function to sign a file
function signFile(filePath, privateKey, publicAddress) {
  // Read file content
  const fileContent = fs.readFileSync(filePath);
  
  // Calculate file hash (to avoid signing large files directly)
  const fileHash = crypto.createHash('sha256').update(fileContent).digest('hex');
  
  // Sign the hash
  const signature = Cypsphare.sign(privateKey, publicAddress, fileHash);
  
  // Create signature file
  const sigData = JSON.stringify({
    filename: filePath,
    hash: fileHash,
    signature: signature,
    publicAddress: publicAddress,
    timestamp: new Date().toISOString()
  });
  
  fs.writeFileSync(`${filePath}.sig`, sigData);
  return sigData;
}

// Function to verify a signed file
function verifyFile(filePath, sigPath) {
  // Read original file
  const fileContent = fs.readFileSync(filePath);
  
  // Calculate file hash
  const fileHash = crypto.createHash('sha256').update(fileContent).digest('hex');
  
  // Read signature data
  const sigData = JSON.parse(fs.readFileSync(sigPath, 'utf8'));
  
  // Verify hash matches
  if (sigData.hash !== fileHash) {
    return { valid: false, reason: 'File has been modified' };
  }
  
  // Verify signature
  const isValid = Cypsphare.verify(
    sigData.publicAddress,
    fileHash,
    sigData.signature
  );
  
  return { 
    valid: isValid, 
    reason: isValid ? 'Signature valid' : 'Invalid signature' 
  };
}

// Usage example
const keyPair = Cypsphare.generateKeyPair();
signFile('important-document.pdf', keyPair.privateKey, keyPair.publicAddress);
const result = verifyFile('important-document.pdf', 'important-document.pdf.sig');
console.log(`Verification result: ${result.valid ? 'Success' : 'Failed'} - ${result.reason}`);
```

### Authentication System

```javascript
const Cypsphare = require('cypsphare');
const crypto = require('crypto');

class CypsphareAuth {
  constructor() {
    this.users = new Map();  // publicAddress -> user data
    this.challenges = new Map();  // publicAddress -> challenge
  }
  
  // Register a new user
  registerUser(username, publicAddress) {
    if (this.getUserByAddress(publicAddress)) {
      throw new Error('Address already registered');
    }
    
    this.users.set(publicAddress, { 
      username, 
      publicAddress,
      registeredAt: new Date().toISOString()
    });
    
    return this.users.get(publicAddress);
  }
  
  // Get user by public address
  getUserByAddress(publicAddress) {
    return this.users.get(publicAddress);
  }
  
  // Generate a challenge for authentication
  generateChallenge(publicAddress) {
    const user = this.getUserByAddress(publicAddress);
    if (!user) {
      throw new Error('User not found');
    }
    
    // Create a random challenge
    const challenge = crypto.randomBytes(32).toString('hex');
    
    // Store the challenge with expiration time (5 minutes)
    this.challenges.set(publicAddress, {
      challenge,
      expires: Date.now() + 5 * 60 * 1000
    });
    
    return challenge;
  }
  
  // Verify a signed challenge
  verifySignedChallenge(publicAddress, signedChallenge) {
    const challengeData = this.challenges.get(publicAddress);
    
    // Check if challenge exists and is not expired
    if (!challengeData || challengeData.expires < Date.now()) {
      return { 
        success: false, 
        reason: challengeData ? 'Challenge expired' : 'No active challenge'
      };
    }
    
    // Verify the signature
    const isValid = Cypsphare.verify(
      publicAddress,
      challengeData.challenge,
      signedChallenge
    );
    
    // Clear the challenge after verification
    this.challenges.delete(publicAddress);
    
    return {
      success: isValid,
      user: isValid ? this.getUserByAddress(publicAddress) : null,
      reason: isValid ? 'Authentication successful' : 'Invalid signature'
    };
  }
}

// Example usage flow
async function demoAuthFlow() {
  const authSystem = new CypsphareAuth();
  
  // Generate a new key pair (client side)
  const keyPair = Cypsphare.generateKeyPair();
  
  // Register user with the auth system
  authSystem.registerUser('alice', keyPair.publicAddress);
  
  // Authentication flow
  // 1. Client requests a challenge
  const challenge = authSystem.generateChallenge(keyPair.publicAddress);
  
  // 2. Client signs the challenge
  const signature = Cypsphare.sign(
    keyPair.privateKey,
    keyPair.publicAddress,
    challenge
  );
  
  // 3. Server verifies the signature
  const authResult = authSystem.verifySignedChallenge(
    keyPair.publicAddress,
    signature
  );
  
  console.log(`Authentication ${authResult.success ? 'succeeded' : 'failed'}`);
  if (authResult.success) {
    console.log(`Logged in as: ${authResult.user.username}`);
  } else {
    console.log(`Reason: ${authResult.reason}`);
  }
}

demoAuthFlow();
```

### Working with Raw Field and Vector Operations

```javascript
const Cypsphare = require('cypsphare');

// Create field elements
const a = new Cypsphare.GF25686(123456789n);
const b = new Cypsphare.GF25686(987654321n);

// Field operations
const sum = a.add(b);
const product = a.mul(b);

console.log('Field element a:', a.value.toString(16));
console.log('Field element b:', b.value.toString(16));
console.log('a + b =', sum.value.toString(16));
console.log('a * b =', product.value.toString(16));

// Create vectors
const v1 = new Cypsphare.Vector3(
  new Cypsphare.GF25686(1n),
  new Cypsphare.GF25686(2n),
  new Cypsphare.GF25686(3n)
);

const v2 = new Cypsphare.Vector3(
  new Cypsphare.GF25686(4n),
  new Cypsphare.GF25686(5n),
  new Cypsphare.GF25686(6n)
);

// Vector operations
const vectorSum = v1.add(v2);
const scaledVector = v1.scalarMul(a);

console.log('Vector v1:', [v1.x.value, v1.y.value, v1.z.value].map(n => n.toString()));
console.log('Vector v2:', [v2.x.value, v2.y.value, v2.z.value].map(n => n.toString()));
console.log('v1 + v2:', [vectorSum.x.value, vectorSum.y.value, vectorSum.z.value].map(n => n.toString()));
console.log('a * v1:', [scaledVector.x.value, scaledVector.y.value, scaledVector.z.value].map(n => n.toString()));

// Convert to bytes and back
const fieldBytes = a.toBytes();
const recoveredField = Cypsphare.GF25686.fromBytes(fieldBytes);
console.log('Field element recovery works:', a.equals(recoveredField));

const vectorBytes = v1.toBytes();
const recoveredVector = Cypsphare.Vector3.fromBytes(vectorBytes);
console.log('Vector recovery works:', v1.equals(recoveredVector));
```

### Implementing a Simple Blockchain Transaction

```javascript
const Cypsphare = require('cypsphare');
const crypto = require('crypto');

class Transaction {
  constructor(fromAddress, toAddress, amount) {
    this.fromAddress = fromAddress;
    this.toAddress = toAddress;
    this.amount = amount;
    this.timestamp = Date.now();
    this.signature = null;
  }
  
  calculateHash() {
    return Cypsphare.sha256(
      this.fromAddress +
      this.toAddress +
      this.amount +
      this.timestamp
    );
  }
  
  sign(privateKey) {
    if (this.signature) {
      throw new Error('Transaction already signed');
    }
    
    // Verify the signing key matches the sender's address
    const index = parseInt(this.fromAddress.slice(-1), 10);
    const derivedAddress = Cypsphare.privateKeyToPublicAddress(privateKey, index);
    
    if (derivedAddress !== this.fromAddress) {
      throw new Error('Cannot sign transaction with key from another wallet');
    }
    
    // Calculate hash and sign it
    const hash = this.calculateHash();
    this.signature = Cypsphare.sign(privateKey, this.fromAddress, hash);
    return this.signature;
  }
  
  isValid() {
    // Check if it's a coinbase transaction (no sender)
    if (this.fromAddress === null) return true;
    
    // Check if transaction has a signature
    if (!this.signature) {
      throw new Error('Unsigned transaction');
    }
    
    // Verify signature
    return Cypsphare.verify(
      this.fromAddress,
      this.calculateHash(),
      this.signature
    );
  }
}

// Example usage
function createAndVerifyTransaction() {
  // Generate keys for sender and receiver
  const sender = Cypsphare.generateKeyPair();
  const receiver = Cypsphare.generateKeyPair();
  
  // Create a transaction
  const tx = new Transaction(sender.publicAddress, receiver.publicAddress, 100);
  
  // Sign the transaction
  tx.sign(sender.privateKey);
  
  // Verify the transaction
  console.log(`Transaction is valid: ${tx.isValid()}`);
  
  // Try to tamper with the transaction
  const tamperedTx = {...tx, amount: 200};
  console.log(`Tampered transaction valid: ${tamperedTx.isValid()}`); // Should catch this and return false
}

createAndVerifyTransaction();
```

## Performance Benchmarking

```javascript
const Cypsphare = require('cypsphare');
const crypto = require('crypto');

// Function to run a benchmark
function runBenchmark(name, iterations, func) {
  console.log(`Running benchmark: ${name}`);
  
  const start = process.hrtime.bigint();
  
  for (let i = 0; i < iterations; i++) {
    func();
  }
  
  const end = process.hrtime.bigint();
  const timeInMs = Number(end - start) / 1_000_000;
  
  console.log(`Completed ${iterations} iterations in ${timeInMs.toFixed(2)}ms`);
  console.log(`Average: ${(timeInMs / iterations).toFixed(3)}ms per operation`);
  console.log(`Operations per second: ${Math.floor(iterations / (timeInMs / 1000))}`);
  console.log('---');
  
  return timeInMs;
}

// Run various benchmarks
async function runAllBenchmarks() {
  const iterations = 1000;
  const keyPair = Cypsphare.generateKeyPair();
  const message = 'Test message for benchmarking';
  let signature;
  
  // Key generation benchmark
  runBenchmark('Key Generation', 100, () => {
    Cypsphare.generateKeyPair();
  });
  
  // Signing benchmark
  runBenchmark('Message Signing', iterations, () => {
    signature = Cypsphare.sign(keyPair.privateKey, keyPair.publicAddress, message);
  });
  
  // Verification benchmark
  runBenchmark('Signature Verification', iterations, () => {
    Cypsphare.verify(keyPair.publicAddress, message, signature);
  });
  
  // Field operations benchmark
  const a = new Cypsphare.GF25686(BigInt('0x' + crypto.randomBytes(32).toString('hex')));
  const b = new Cypsphare.GF25686(BigInt('0x' + crypto.randomBytes(32).toString('hex')));
  
  runBenchmark('Field Addition', iterations * 10, () => {
    a.add(b);
  });
  
  runBenchmark('Field Multiplication', iterations, () => {
    a.mul(b);
  });
  
  // Vector operations benchmark
  const v1 = new Cypsphare.Vector3(
    new Cypsphare.GF25686(BigInt('0x' + crypto.randomBytes(32).toString('hex'))),
    new Cypsphare.GF25686(BigInt('0x' + crypto.randomBytes(32).toString('hex'))),
    new Cypsphare.GF25686(BigInt('0x' + crypto.randomBytes(32).toString('hex')))
  );
  
  const v2 = new Cypsphare.Vector3(
    new Cypsphare.GF25686(BigInt('0x' + crypto.randomBytes(32).toString('hex'))),
    new Cypsphare.GF25686(BigInt('0x' + crypto.randomBytes(32).toString('hex'))),
    new Cypsphare.GF25686(BigInt('0x' + crypto.randomBytes(32).toString('hex')))
  );
  
  runBenchmark('Vector Addition', iterations * 10, () => {
    v1.add(v2);
  });
  
  runBenchmark('Vector Scalar Multiplication', iterations, () => {
    v1.scalarMul(a);
  });
}

runAllBenchmarks();
```

## License

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
