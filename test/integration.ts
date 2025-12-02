/**
 * test/integration.ts
 *
 * Integration test demonstrating the complete Blind Imageboard flow.
 * Run with: npm test (or: npx tsx test/integration.ts)
 */

import {
  generateIdentityKeypair,
  preparePost,
  decryptPost,
  extractKeyFromFragment,
  filterPosts,
  base64ToBytes,
} from '../client/cryptoLogic.js';
import type { EncryptedPayload } from '../shared/types.js';
import nacl from 'tweetnacl';

const SERVER_URL = 'http://localhost:3000';

// ANSI colors for output
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const RESET = '\x1b[0m';

function log(msg: string): void {
  console.log(msg);
}

function pass(test: string): void {
  console.log(`${GREEN}✓ PASS${RESET}: ${test}`);
}

function fail(test: string, error: unknown): void {
  console.log(`${RED}✗ FAIL${RESET}: ${test}`);
  console.log(`  Error: ${error}`);
}

async function runTests(): Promise<void> {
  log(`\n${CYAN}═══════════════════════════════════════════════════════════════${RESET}`);
  log(`${CYAN}       BLIND IMAGEBOARD - Integration Tests${RESET}`);
  log(`${CYAN}═══════════════════════════════════════════════════════════════${RESET}\n`);

  let passed = 0;
  let failed = 0;

  // =========================================================================
  // TEST 1: Identity Generation
  // =========================================================================
  try {
    log(`${YELLOW}[TEST 1]${RESET} Identity Keypair Generation`);
    const identity = generateIdentityKeypair();

    if (!identity.publicKey || !identity.privateKey) {
      throw new Error('Missing keys in generated identity');
    }

    const pubKeyBytes = base64ToBytes(identity.publicKey);
    const privKeyBytes = base64ToBytes(identity.privateKey);

    if (pubKeyBytes.length !== 32) {
      throw new Error(`Public key wrong size: ${pubKeyBytes.length} (expected 32)`);
    }
    if (privKeyBytes.length !== 64) {
      throw new Error(`Private key wrong size: ${privKeyBytes.length} (expected 64)`);
    }

    pass('Identity keypair generated with correct key sizes');
    log(`  Public key: ${identity.publicKey.substring(0, 20)}...`);
    passed++;
  } catch (e) {
    fail('Identity keypair generation', e);
    failed++;
  }

  // =========================================================================
  // TEST 2: Local Encryption/Decryption (no server)
  // =========================================================================
  try {
    log(`\n${YELLOW}[TEST 2]${RESET} Local Encryption → Decryption Round-trip`);

    const identity = generateIdentityKeypair();
    const originalContent = 'Secret message: The quick brown fox jumps over the lazy dog!';

    // Encrypt
    const { payload, urlFragment, symmetricKey } = preparePost(originalContent, identity);

    log(`  Original: "${originalContent}"`);
    log(`  Ciphertext (truncated): ${payload.ciphertext.substring(0, 30)}...`);
    log(`  URL Fragment: ${urlFragment.substring(0, 30)}...`);

    // Simulate server storage (just add id and timestamp)
    const storedPayload: EncryptedPayload = {
      id: 'test-001',
      ...payload,
      timestamp: new Date().toISOString(),
    };

    // Extract key from fragment (as browser would do)
    const extractedKey = extractKeyFromFragment(urlFragment);
    if (!extractedKey) {
      throw new Error('Failed to extract key from URL fragment');
    }

    // Decrypt
    const decrypted = decryptPost(storedPayload, extractedKey);

    if (decrypted.content !== originalContent) {
      throw new Error(`Content mismatch: got "${decrypted.content}"`);
    }
    if (!decrypted.signatureValid) {
      throw new Error('Signature validation failed');
    }

    pass('Encryption/decryption round-trip successful');
    log(`  Decrypted: "${decrypted.content}"`);
    log(`  Signature valid: ${decrypted.signatureValid}`);
    passed++;
  } catch (e) {
    fail('Local encryption/decryption', e);
    failed++;
  }

  // =========================================================================
  // TEST 3: Signature Verification
  // =========================================================================
  try {
    log(`\n${YELLOW}[TEST 3]${RESET} Signature Prevents Tampering`);

    const identity = generateIdentityKeypair();
    const { payload, symmetricKey } = preparePost('Original message', identity);

    // Tamper with the ciphertext by modifying actual bytes
    const originalBytes = base64ToBytes(payload.ciphertext);
    const tamperedBytes = new Uint8Array(originalBytes);
    tamperedBytes[0] = (tamperedBytes[0] + 1) % 256; // Flip first byte
    const tamperedCiphertext = Buffer.from(tamperedBytes).toString('base64');

    const tamperedPayload: EncryptedPayload = {
      id: 'tampered-001',
      ...payload,
      ciphertext: tamperedCiphertext,
      timestamp: new Date().toISOString(),
    };

    // Verify signature fails for tampered data
    const cipherBytes = base64ToBytes(tamperedPayload.ciphertext);
    const sigBytes = base64ToBytes(tamperedPayload.signature);
    const pubKeyBytes = base64ToBytes(tamperedPayload.authorPublicKey);

    const isValid = nacl.sign.detached.verify(cipherBytes, sigBytes, pubKeyBytes);

    if (isValid) {
      throw new Error('Signature should have been invalid for tampered data!');
    }

    pass('Tampered ciphertext correctly fails signature verification');
    passed++;
  } catch (e) {
    fail('Signature verification', e);
    failed++;
  }

  // =========================================================================
  // TEST 4: Web of Trust Filtering
  // =========================================================================
  try {
    log(`\n${YELLOW}[TEST 4]${RESET} Web of Trust - Block List Filtering`);

    const alice = generateIdentityKeypair();
    const bob = generateIdentityKeypair();
    const spammer = generateIdentityKeypair();

    // Create posts from different authors
    const alicePost: EncryptedPayload = {
      id: 'alice-001',
      ...preparePost('Hello from Alice', alice).payload,
      timestamp: new Date().toISOString(),
    };

    const bobPost: EncryptedPayload = {
      id: 'bob-001',
      ...preparePost('Hello from Bob', bob).payload,
      timestamp: new Date().toISOString(),
    };

    const spamPost: EncryptedPayload = {
      id: 'spam-001',
      ...preparePost('BUY CRYPTO NOW!!!', spammer).payload,
      timestamp: new Date().toISOString(),
    };

    const allPosts = [alicePost, bobPost, spamPost];
    log(`  Total posts: ${allPosts.length}`);

    // Filter out the spammer
    const filtered = filterPosts(allPosts, [spammer.publicKey]);

    if (filtered.length !== 2) {
      throw new Error(`Expected 2 posts after filter, got ${filtered.length}`);
    }

    if (filtered.some((p) => p.authorPublicKey === spammer.publicKey)) {
      throw new Error('Spammer post should have been filtered out');
    }

    pass('Block list filtering works correctly');
    log(`  Posts after filtering: ${filtered.length}`);
    passed++;
  } catch (e) {
    fail('Web of Trust filtering', e);
    failed++;
  }

  // =========================================================================
  // TEST 5: Server Integration (requires running server)
  // =========================================================================
  log(`\n${YELLOW}[TEST 5]${RESET} Server Integration (POST & GET)`);

  try {
    // Check if server is running
    const healthCheck = await fetch(`${SERVER_URL}/api/health`).catch(() => null);

    if (!healthCheck || !healthCheck.ok) {
      log(`  ${YELLOW}⚠ SKIPPED${RESET}: Server not running at ${SERVER_URL}`);
      log(`  Start server with: ${CYAN}npm run dev${RESET}`);
    } else {
      const identity = generateIdentityKeypair();
      const testContent = `Test post at ${new Date().toISOString()}`;
      const { payload, symmetricKey } = preparePost(testContent, identity);

      // POST to server
      const publishResponse = await fetch(`${SERVER_URL}/api/publish`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!publishResponse.ok) {
        const err = await publishResponse.json();
        throw new Error(`Publish failed: ${err.error}`);
      }

      const publishResult = await publishResponse.json();
      log(`  Published with ID: ${publishResult.id}`);

      // GET from server
      const getResponse = await fetch(`${SERVER_URL}/api/posts/${publishResult.id}`);
      if (!getResponse.ok) {
        throw new Error('Failed to fetch published post');
      }

      const fetchedPayload = (await getResponse.json()) as EncryptedPayload;

      // Decrypt the fetched payload
      const decrypted = decryptPost(fetchedPayload, symmetricKey);

      if (decrypted.content !== testContent) {
        throw new Error('Decrypted content does not match original');
      }

      pass('Server publish and fetch successful');
      log(`  Content verified: "${decrypted.content.substring(0, 40)}..."`);
      passed++;
    }
  } catch (e) {
    fail('Server integration', e);
    failed++;
  }

  // =========================================================================
  // TEST 6: Wrong Key Fails Decryption
  // =========================================================================
  try {
    log(`\n${YELLOW}[TEST 6]${RESET} Wrong Key Fails Decryption`);

    const identity = generateIdentityKeypair();
    const { payload } = preparePost('Secret message', identity);

    const storedPayload: EncryptedPayload = {
      id: 'wrong-key-test',
      ...payload,
      timestamp: new Date().toISOString(),
    };

    // Generate a random wrong key
    const wrongKey = Buffer.from(nacl.randomBytes(32)).toString('base64');

    try {
      decryptPost(storedPayload, wrongKey);
      throw new Error('Decryption should have failed with wrong key!');
    } catch (e) {
      if (e instanceof Error && e.message.includes('Decryption failed')) {
        pass('Wrong key correctly rejected');
        passed++;
      } else {
        throw e;
      }
    }
  } catch (e) {
    fail('Wrong key rejection', e);
    failed++;
  }

  // =========================================================================
  // SUMMARY
  // =========================================================================
  log(`\n${CYAN}═══════════════════════════════════════════════════════════════${RESET}`);
  log(`${CYAN}                        TEST SUMMARY${RESET}`);
  log(`${CYAN}═══════════════════════════════════════════════════════════════${RESET}`);
  log(`  ${GREEN}Passed${RESET}: ${passed}`);
  log(`  ${RED}Failed${RESET}: ${failed}`);
  log(`  Total: ${passed + failed}\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

// Run tests
runTests().catch(console.error);
