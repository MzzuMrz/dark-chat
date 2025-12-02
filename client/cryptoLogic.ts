/**
 * client/cryptoLogic.ts
 *
 * Client-side cryptographic operations for the Blind Imageboard.
 *
 * CORE PRINCIPLE: All encryption/decryption happens HERE, in the browser.
 * The server NEVER sees plaintext or decryption keys.
 *
 * KEY INSIGHT: URL fragments (everything after #) are NEVER sent to servers.
 * This is part of the URI specification (RFC 3986). We exploit this to
 * share decryption keys via URLs while keeping the server blind.
 */

import nacl from 'tweetnacl';
import {
  EncryptedPayload,
  PublishRequest,
  PublishResult,
  DecryptedPost,
  IdentityKeypair,
} from '../shared/types';

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Converts a Uint8Array to base64 string.
 */
function bytesToBase64(bytes: Uint8Array): string {
  // Browser-compatible approach
  if (typeof window !== 'undefined' && typeof window.btoa === 'function') {
    const binary = Array.from(bytes)
      .map((b) => String.fromCharCode(b))
      .join('');
    return window.btoa(binary);
  }
  // Node.js fallback
  return Buffer.from(bytes).toString('base64');
}

/**
 * Converts a base64 string to Uint8Array.
 */
function base64ToBytes(base64: string): Uint8Array {
  // Browser-compatible approach
  if (typeof window !== 'undefined' && typeof window.atob === 'function') {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
  // Node.js fallback
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

/**
 * Converts a string to UTF-8 encoded Uint8Array.
 */
function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Converts UTF-8 encoded Uint8Array to string.
 */
function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

// ============================================================================
// IDENTITY MANAGEMENT
// ============================================================================

/**
 * Generates a new Ed25519 identity keypair for signing posts.
 *
 * PRIVACY CONSIDERATION:
 * Each keypair is a pseudonymous identity. Users can:
 * - Use one keypair for all posts (consistent identity)
 * - Generate new keypairs for anonymity (unlinkable posts)
 *
 * The private key should be stored securely (e.g., encrypted localStorage).
 */
export function generateIdentityKeypair(): IdentityKeypair {
  const keypair = nacl.sign.keyPair();

  return {
    publicKey: bytesToBase64(keypair.publicKey),
    privateKey: bytesToBase64(keypair.secretKey),
  };
}

/**
 * Reconstructs a keypair from stored private key.
 */
export function keypairFromPrivateKey(privateKeyBase64: string): IdentityKeypair {
  const privateKey = base64ToBytes(privateKeyBase64);

  // Ed25519 secret keys contain the public key in the last 32 bytes
  const publicKey = privateKey.slice(32);

  return {
    publicKey: bytesToBase64(publicKey),
    privateKey: privateKeyBase64,
  };
}

// ============================================================================
// PUBLISHING FLOW (ENCRYPTION)
// ============================================================================

/**
 * Encrypts content and prepares it for publishing.
 *
 * PLAUSIBLE DENIABILITY MECHANISM:
 * 1. We generate a RANDOM symmetric key for each post
 * 2. Content is encrypted with this key using nacl.secretbox (XSalsa20-Poly1305)
 * 3. The key is returned in the URL fragment (#key=...)
 * 4. The fragment is NEVER sent to the server (browser behavior per RFC 3986)
 *
 * Result: Server stores ciphertext but CANNOT decrypt it.
 *
 * @param content - The plaintext content to encrypt (text, stringified JSON, etc.)
 * @param identity - The author's signing keypair
 * @returns Object containing:
 *   - payload: Data to send to server (encrypted, no secrets)
 *   - urlFragment: String to append to URL (#key=...)
 *   - symmetricKey: The raw key for programmatic use
 */
export function preparePost(content: string, identity: IdentityKeypair): PublishResult {
  // Step 1: Generate a random one-time symmetric key
  // WHY: Each post gets a unique key. Compromising one key doesn't compromise others.
  const symmetricKey = nacl.randomBytes(nacl.secretbox.keyLength);

  // Step 2: Generate a random nonce
  // WHY: Ensures identical plaintexts produce different ciphertexts
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);

  // Step 3: Encrypt the content
  // ALGORITHM: XSalsa20-Poly1305 (authenticated encryption)
  // This provides both confidentiality AND integrity
  const contentBytes = stringToBytes(content);
  const ciphertext = nacl.secretbox(contentBytes, nonce, symmetricKey);

  // Step 4: Sign the CIPHERTEXT (not plaintext)
  // WHY: Server can verify authenticity without knowing content
  // IMPORTANT: We sign the ciphertext, not the plaintext. This means:
  // - Server can verify the signature
  // - But signature reveals nothing about what was signed
  const privateKey = base64ToBytes(identity.privateKey);
  const signature = nacl.sign.detached(ciphertext, privateKey);

  // Step 5: Construct the payload for the server
  const payload: PublishRequest = {
    ciphertext: bytesToBase64(ciphertext),
    nonce: bytesToBase64(nonce),
    authorPublicKey: identity.publicKey,
    signature: bytesToBase64(signature),
  };

  // Step 6: Construct the URL fragment containing the decryption key
  // CRITICAL: This fragment stays in the browser. It is NEVER sent to the server.
  // When you visit example.com/post/123#key=abc, the server only sees /post/123
  const symmetricKeyBase64 = bytesToBase64(symmetricKey);
  const urlFragment = `#key=${encodeURIComponent(symmetricKeyBase64)}`;

  return {
    payload,
    urlFragment,
    symmetricKey: symmetricKeyBase64,
  };
}

/**
 * Publishes a post to the server.
 *
 * @param serverUrl - Base URL of the server (e.g., 'http://localhost:3000')
 * @param content - The plaintext content to publish
 * @param identity - The author's signing keypair
 * @returns Object containing server response and shareable URL
 */
export async function publishPost(
  serverUrl: string,
  content: string,
  identity: IdentityKeypair
): Promise<{ postId: string; shareableUrl: string; symmetricKey: string }> {
  // Prepare the encrypted payload
  const { payload, urlFragment, symmetricKey } = preparePost(content, identity);

  // Send to server
  const response = await fetch(`${serverUrl}/api/publish`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error ?? 'Failed to publish post');
  }

  const result = await response.json();
  const postId = result.id as string;

  // Construct the shareable URL
  // The fragment contains the decryption key - share this carefully!
  const shareableUrl = `${serverUrl}/post/${postId}${urlFragment}`;

  return {
    postId,
    shareableUrl,
    symmetricKey,
  };
}

// ============================================================================
// READING FLOW (DECRYPTION)
// ============================================================================

/**
 * Extracts the decryption key from a URL fragment.
 *
 * Expected format: #key=<base64-encoded-key>
 *
 * SECURITY: In a real app, get this from window.location.hash
 * The hash is available to JavaScript but was never sent to the server.
 */
export function extractKeyFromFragment(fragment: string): string | null {
  // Remove leading # if present
  const cleanFragment = fragment.startsWith('#') ? fragment.slice(1) : fragment;

  // Parse as query string
  const params = new URLSearchParams(cleanFragment);
  const key = params.get('key');

  if (!key) {
    return null;
  }

  return decodeURIComponent(key);
}

/**
 * Decrypts a post using the symmetric key from the URL fragment.
 *
 * VERIFICATION STEPS:
 * 1. Verify the signature (proves author identity, not tampered)
 * 2. Decrypt the ciphertext (requires the key from URL fragment)
 *
 * If signature verification fails, we still return the decrypted content
 * but flag signatureValid as false. This allows users to see the content
 * while knowing it may be tampered with.
 */
export function decryptPost(
  encryptedPayload: EncryptedPayload,
  symmetricKeyBase64: string
): DecryptedPost {
  // Step 1: Decode all the base64 values
  const ciphertext = base64ToBytes(encryptedPayload.ciphertext);
  const nonce = base64ToBytes(encryptedPayload.nonce);
  const authorPublicKey = base64ToBytes(encryptedPayload.authorPublicKey);
  const signature = base64ToBytes(encryptedPayload.signature);
  const symmetricKey = base64ToBytes(symmetricKeyBase64);

  // Step 2: Verify the signature
  // This proves the ciphertext wasn't modified and came from the stated author
  const signatureValid = nacl.sign.detached.verify(ciphertext, signature, authorPublicKey);

  // Step 3: Decrypt the content
  // nacl.secretbox.open returns null if decryption fails (wrong key or tampering)
  const decrypted = nacl.secretbox.open(ciphertext, nonce, symmetricKey);

  if (!decrypted) {
    throw new Error('Decryption failed: invalid key or corrupted ciphertext');
  }

  const content = bytesToString(decrypted);

  return {
    encryptedPayload,
    content,
    signatureValid,
  };
}

/**
 * Fetches and decrypts a post from the server.
 *
 * @param serverUrl - Base URL of the server
 * @param postId - The post ID to fetch
 * @param symmetricKeyBase64 - The decryption key (from URL fragment)
 */
export async function fetchAndDecryptPost(
  serverUrl: string,
  postId: string,
  symmetricKeyBase64: string
): Promise<DecryptedPost> {
  const response = await fetch(`${serverUrl}/api/posts/${postId}`);

  if (!response.ok) {
    throw new Error('Post not found');
  }

  const encryptedPayload = (await response.json()) as EncryptedPayload;
  return decryptPost(encryptedPayload, symmetricKeyBase64);
}

/**
 * Fetches all posts and attempts to decrypt those for which we have keys.
 *
 * USAGE: Pass a Map of postId -> symmetricKey for posts you can decrypt.
 * Posts without keys in the map will be returned as null.
 */
export async function fetchAndDecryptPosts(
  serverUrl: string,
  keys: Map<string, string>
): Promise<Map<string, DecryptedPost | null>> {
  const response = await fetch(`${serverUrl}/api/posts`);
  const { posts } = (await response.json()) as { posts: EncryptedPayload[] };

  const results = new Map<string, DecryptedPost | null>();

  for (const post of posts) {
    const key = keys.get(post.id);
    if (key) {
      try {
        results.set(post.id, decryptPost(post, key));
      } catch {
        results.set(post.id, null);
      }
    } else {
      results.set(post.id, null);
    }
  }

  return results;
}

// ============================================================================
// WEB OF TRUST (WoT) FILTERING
// ============================================================================

/**
 * Filters posts based on blocked public keys.
 *
 * WEB OF TRUST CONCEPT:
 * Users maintain their own list of trusted/blocked public keys.
 * This filtering happens CLIENT-SIDE, before decryption.
 *
 * WHY FILTER BEFORE DECRYPTION?
 * 1. Efficiency: Don't waste CPU cycles decrypting spam
 * 2. Safety: Don't render potentially malicious content
 * 3. Privacy: Filtering locally means server doesn't know your trust list
 *
 * @param posts - Array of encrypted posts from server
 * @param blockedPubKeys - Array of public keys to filter out
 * @returns Filtered array with blocked authors removed
 */
export function filterPosts(
  posts: EncryptedPayload[],
  blockedPubKeys: string[]
): EncryptedPayload[] {
  const blockedSet = new Set(blockedPubKeys);

  return posts.filter((post) => !blockedSet.has(post.authorPublicKey));
}

/**
 * Filters posts to show only from trusted authors.
 *
 * Use this for a "friends only" view where you only see
 * posts from explicitly trusted public keys.
 */
export function filterToTrusted(
  posts: EncryptedPayload[],
  trustedPubKeys: string[]
): EncryptedPayload[] {
  const trustedSet = new Set(trustedPubKeys);

  return posts.filter((post) => trustedSet.has(post.authorPublicKey));
}

/**
 * Groups posts by author public key.
 *
 * Useful for displaying posts organized by pseudonymous identity.
 */
export function groupByAuthor(
  posts: EncryptedPayload[]
): Map<string, EncryptedPayload[]> {
  const groups = new Map<string, EncryptedPayload[]>();

  for (const post of posts) {
    const authorPosts = groups.get(post.authorPublicKey) ?? [];
    authorPosts.push(post);
    groups.set(post.authorPublicKey, authorPosts);
  }

  return groups;
}

// ============================================================================
// EXAMPLE USAGE
// ============================================================================

/**
 * Example demonstrating the complete flow.
 *
 * In a real application:
 * - Identity would be stored in encrypted localStorage
 * - Keys would be stored in a local database keyed by post URL
 * - The URL fragment would come from window.location.hash
 */
export async function exampleUsage(): Promise<void> {
  const SERVER_URL = 'http://localhost:3000';

  // ========== PUBLISHING ==========
  console.log('=== Publishing Flow ===');

  // Generate or load an identity
  const myIdentity = generateIdentityKeypair();
  console.log('My public key:', myIdentity.publicKey);

  // Prepare a post
  const content = 'Hello, this is a secret message!';
  const { payload, urlFragment, symmetricKey } = preparePost(content, myIdentity);

  console.log('Payload to send to server:', payload);
  console.log('URL fragment (KEEP SECRET):', urlFragment);
  console.log('Symmetric key:', symmetricKey);

  // In real usage, you would:
  // 1. POST `payload` to server
  // 2. Construct shareable URL: serverUrl + '/post/' + postId + urlFragment
  // 3. Share the URL with intended recipients

  // ========== READING ==========
  console.log('\n=== Reading Flow ===');

  // Simulate receiving a URL like: http://localhost:3000/post/abc123#key=...
  const receivedUrl = `${SERVER_URL}/post/abc123${urlFragment}`;
  console.log('Received URL:', receivedUrl);

  // Extract the key from fragment
  const hash = new URL(receivedUrl).hash;
  const extractedKey = extractKeyFromFragment(hash);
  console.log('Extracted key:', extractedKey);

  // Simulate an encrypted payload (in reality, fetch from server)
  const mockEncryptedPayload: EncryptedPayload = {
    id: 'abc123',
    ...payload,
    timestamp: new Date().toISOString(),
  };

  // Decrypt the post
  if (extractedKey) {
    const decrypted = decryptPost(mockEncryptedPayload, extractedKey);
    console.log('Decrypted content:', decrypted.content);
    console.log('Signature valid:', decrypted.signatureValid);
  }

  // ========== WEB OF TRUST ==========
  console.log('\n=== Web of Trust Filtering ===');

  const spammerPubKey = 'spammer-public-key-here';
  const mockPosts: EncryptedPayload[] = [
    mockEncryptedPayload,
    { ...mockEncryptedPayload, id: 'spam1', authorPublicKey: spammerPubKey },
  ];

  const filtered = filterPosts(mockPosts, [spammerPubKey]);
  console.log('Posts before filter:', mockPosts.length);
  console.log('Posts after filter:', filtered.length);
}

// Export all utilities for use in the application
export {
  bytesToBase64,
  base64ToBytes,
  stringToBytes,
  bytesToString,
};
