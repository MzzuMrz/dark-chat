/**
 * shared/types.ts
 *
 * Type definitions for the Blind Imageboard.
 * These interfaces define the data structures that flow between client and server.
 *
 * PLAUSIBLE DENIABILITY PRINCIPLE:
 * Notice that NO decryption key is defined here. The symmetric key used to encrypt
 * content is NEVER transmitted to the server. It exists only in URL fragments
 * (which browsers don't send to servers) and in the client's memory.
 */

/**
 * The encrypted payload stored on the server.
 * The server can verify authenticity (signature) but CANNOT read content (ciphertext).
 */
export interface EncryptedPayload {
  /** Unique identifier for the post (server-generated, e.g., timestamp + random) */
  id: string;

  /**
   * The encrypted content (post text, image data, etc.)
   * Base64-encoded output of nacl.secretbox()
   *
   * PRIVACY: Server sees only random-looking bytes. Without the symmetric key
   * (which is in the URL fragment), this is computationally indistinguishable
   * from random noise.
   */
  ciphertext: string;

  /**
   * Nonce used for symmetric encryption.
   * Base64-encoded, 24 bytes for nacl.secretbox.
   *
   * NOTE: Nonces can be public. They only ensure the same key+plaintext
   * produces different ciphertext each time. Revealing the nonce without
   * the key reveals nothing about the plaintext.
   */
  nonce: string;

  /**
   * The author's public signing key (Ed25519).
   * Base64-encoded, 32 bytes.
   *
   * PURPOSE: Allows clients to:
   * 1. Verify the signature (spam prevention)
   * 2. Build a Web of Trust (block/follow authors by pubkey)
   *
   * PRIVACY TRADEOFF: This is a pseudonymous identifier. The server knows
   * "pubkey X posted Y times" but not WHO owns that pubkey.
   */
  authorPublicKey: string;

  /**
   * Ed25519 signature over the ciphertext.
   * Base64-encoded, 64 bytes.
   *
   * SPAM PREVENTION: Server verifies this before storing. Proves the author
   * possesses the private key corresponding to authorPublicKey.
   *
   * PLAUSIBLE DENIABILITY: The signature is over CIPHERTEXT, not plaintext.
   * The server cannot prove what content was signed, only that "some bytes"
   * were signed by a specific keypair.
   */
  signature: string;

  /**
   * Server timestamp when the post was received.
   * ISO 8601 format.
   *
   * NOTE: This is server-generated metadata. For stronger privacy,
   * consider adding random delays or batching posts.
   */
  timestamp: string;
}

/**
 * Request body for publishing a new post.
 * Excludes server-generated fields (id, timestamp).
 */
export interface PublishRequest {
  ciphertext: string;
  nonce: string;
  authorPublicKey: string;
  signature: string;
}

/**
 * Response from the publish endpoint.
 */
export interface PublishResponse {
  success: boolean;
  id?: string;
  error?: string;
}

/**
 * Response from the posts listing endpoint.
 */
export interface PostsResponse {
  posts: EncryptedPayload[];
}

/**
 * Decrypted post content (exists ONLY on client side).
 * This structure NEVER touches the server.
 */
export interface DecryptedPost {
  /** The original encrypted payload (for reference) */
  encryptedPayload: EncryptedPayload;

  /** The decrypted plaintext content */
  content: string;

  /** Whether the signature was valid */
  signatureValid: boolean;
}

/**
 * Result of a publish operation on the client.
 * Contains both the server payload AND the secret URL fragment.
 */
export interface PublishResult {
  /** The payload to send to the server (no secrets) */
  payload: PublishRequest;

  /**
   * The URL fragment containing the decryption key.
   * Format: "#key=<base64-encoded-symmetric-key>"
   *
   * CRITICAL: This MUST be appended to URLs as a fragment (after #).
   * Browsers NEVER send URL fragments to servers. This is the core
   * mechanism enabling plausible deniability.
   */
  urlFragment: string;

  /**
   * The raw symmetric key (for programmatic use).
   * Base64-encoded, 32 bytes for nacl.secretbox.
   */
  symmetricKey: string;
}

/**
 * Identity keypair for signing posts.
 * The private key should be stored securely on the client (e.g., IndexedDB with encryption).
 */
export interface IdentityKeypair {
  /** Ed25519 public key, base64-encoded */
  publicKey: string;

  /** Ed25519 private key, base64-encoded. NEVER send to server. */
  privateKey: string;
}
