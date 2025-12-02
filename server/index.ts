/**
 * server/index.ts
 *
 * "Blind Relay" server for the Blind Imageboard.
 *
 * PLAUSIBLE DENIABILITY ARCHITECTURE:
 * This server is intentionally "blind" - it stores encrypted data but has
 * NO capability to decrypt it. Even under legal compulsion, the operator
 * can truthfully state: "I cannot read what is stored."
 *
 * The server's only "intelligent" action is signature verification,
 * which prevents spam without requiring knowledge of content.
 */

import express, { Request, Response, NextFunction } from 'express';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import nacl from 'tweetnacl';
import {
  EncryptedPayload,
  PublishRequest,
  PublishResponse,
  PostsResponse,
} from '../shared/types';

// ============================================================================
// CONFIGURATION
// ============================================================================

const PORT = process.env.PORT ?? 3000;

/**
 * Maximum payload size in bytes.
 * Prevents memory exhaustion attacks.
 */
const MAX_PAYLOAD_SIZE = 1024 * 1024; // 1MB

/**
 * Maximum number of posts to store.
 * When exceeded, oldest posts are removed (FIFO).
 *
 * PRIVACY NOTE: Automatic deletion reduces the window of exposure
 * and creates genuine uncertainty about what was ever stored.
 */
const MAX_POSTS = 1000;

// ============================================================================
// IN-MEMORY STORAGE
// ============================================================================

/**
 * Volatile storage - all data is lost on restart.
 *
 * PLAUSIBLE DENIABILITY: Using RAM-only storage means:
 * 1. No disk forensics possible after shutdown
 * 2. Operator can claim any specific content "might have been deleted"
 * 3. Reduces legal exposure (data doesn't persist)
 *
 * For production, consider encrypted disk storage with secure deletion,
 * but RAM-only provides the strongest deniability guarantees.
 */
const posts: EncryptedPayload[] = [];

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Decodes a base64 string to Uint8Array.
 * Returns null if decoding fails.
 */
function base64ToBytes(base64: string): Uint8Array | null {
  try {
    const binary = Buffer.from(base64, 'base64');
    return new Uint8Array(binary);
  } catch {
    return null;
  }
}

/**
 * Generates a unique post ID.
 * Combines timestamp with random bytes for collision resistance.
 */
function generatePostId(): string {
  const timestamp = Date.now().toString(36);
  const random = Buffer.from(nacl.randomBytes(8)).toString('hex');
  return `${timestamp}-${random}`;
}

/**
 * Validates the structure of a PublishRequest.
 * Returns an error message or null if valid.
 */
function validatePublishRequest(body: unknown): string | null {
  if (typeof body !== 'object' || body === null) {
    return 'Request body must be an object';
  }

  const req = body as Record<string, unknown>;

  // Check required fields exist and are strings
  const requiredFields = ['ciphertext', 'nonce', 'authorPublicKey', 'signature'];
  for (const field of requiredFields) {
    if (typeof req[field] !== 'string') {
      return `Missing or invalid field: ${field}`;
    }
  }

  // Validate base64 encoding and expected lengths
  const ciphertext = base64ToBytes(req['ciphertext'] as string);
  if (!ciphertext) {
    return 'Invalid base64 encoding for ciphertext';
  }

  const nonce = base64ToBytes(req['nonce'] as string);
  if (!nonce || nonce.length !== nacl.secretbox.nonceLength) {
    return `Invalid nonce: expected ${nacl.secretbox.nonceLength} bytes`;
  }

  const authorPublicKey = base64ToBytes(req['authorPublicKey'] as string);
  if (!authorPublicKey || authorPublicKey.length !== nacl.sign.publicKeyLength) {
    return `Invalid authorPublicKey: expected ${nacl.sign.publicKeyLength} bytes`;
  }

  const signature = base64ToBytes(req['signature'] as string);
  if (!signature || signature.length !== nacl.sign.signatureLength) {
    return `Invalid signature: expected ${nacl.sign.signatureLength} bytes`;
  }

  return null;
}

/**
 * Verifies the Ed25519 signature over the ciphertext.
 *
 * SPAM PREVENTION WITHOUT CONTENT KNOWLEDGE:
 * We verify that the author possesses the private key corresponding to
 * authorPublicKey by checking the signature. This prevents:
 * - Anonymous spam (no identity = no accountability)
 * - Impersonation (can't sign as someone else)
 *
 * But we still don't know WHAT was signed (it's encrypted).
 */
function verifySignature(request: PublishRequest): boolean {
  try {
    const ciphertext = base64ToBytes(request.ciphertext);
    const signature = base64ToBytes(request.signature);
    const publicKey = base64ToBytes(request.authorPublicKey);

    if (!ciphertext || !signature || !publicKey) {
      return false;
    }

    // nacl.sign.detached.verify returns true if signature is valid
    return nacl.sign.detached.verify(ciphertext, signature, publicKey);
  } catch {
    return false;
  }
}

// ============================================================================
// EXPRESS SERVER SETUP
// ============================================================================

const app = express();

/**
 * PRIVACY: Disable Express headers that leak server information.
 */
app.disable('x-powered-by');

/**
 * PRIVACY: Custom middleware to prevent IP logging.
 *
 * By default, Express/Morgan log IPs. We explicitly avoid this.
 * The server should have NO knowledge of who posted what.
 */
app.use((_req: Request, _res: Response, next: NextFunction) => {
  // Intentionally NOT logging request details
  // In production, consider running behind Tor hidden service
  next();
});

/**
 * Parse JSON bodies with size limit.
 */
app.use(express.json({ limit: MAX_PAYLOAD_SIZE }));

/**
 * CORS headers for browser clients.
 * Adjust origins as needed for production.
 */
app.use((req: Request, res: Response, next: NextFunction) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.sendStatus(204);
    return;
  }

  next();
});

// ============================================================================
// STATIC FILES
// ============================================================================

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const publicPath = join(__dirname, '..', 'public');

app.use(express.static(publicPath));

// ============================================================================
// API ENDPOINTS
// ============================================================================

/**
 * POST /api/publish
 *
 * Accepts an encrypted payload and stores it after signature verification.
 *
 * WHAT THE SERVER KNOWS:
 * - A specific public key signed some bytes
 * - The timestamp of submission
 *
 * WHAT THE SERVER CANNOT KNOW:
 * - The content of the post (encrypted)
 * - The identity of the poster (just a pubkey)
 * - The decryption key (in URL fragment, never sent to server)
 */
app.post('/api/publish', (req: Request, res: Response<PublishResponse>) => {
  // Validate request structure
  const validationError = validatePublishRequest(req.body);
  if (validationError) {
    res.status(400).json({
      success: false,
      error: validationError,
    });
    return;
  }

  const publishRequest = req.body as PublishRequest;

  // Verify signature - spam prevention without content knowledge
  if (!verifySignature(publishRequest)) {
    res.status(403).json({
      success: false,
      error: 'Invalid signature',
    });
    return;
  }

  // Create the stored payload with server-generated metadata
  const encryptedPayload: EncryptedPayload = {
    id: generatePostId(),
    ciphertext: publishRequest.ciphertext,
    nonce: publishRequest.nonce,
    authorPublicKey: publishRequest.authorPublicKey,
    signature: publishRequest.signature,
    timestamp: new Date().toISOString(),
  };

  // Store the payload
  posts.push(encryptedPayload);

  // Enforce maximum posts limit (FIFO eviction)
  while (posts.length > MAX_POSTS) {
    posts.shift();
  }

  /**
   * LOG NOTE: We intentionally do NOT log:
   * - IP address
   * - User agent
   * - Any identifying information
   *
   * This is NOT negligence - it's a privacy feature.
   */

  res.status(201).json({
    success: true,
    id: encryptedPayload.id,
  });
});

/**
 * GET /api/posts
 *
 * Returns all stored encrypted payloads.
 *
 * PLAUSIBLE DENIABILITY: Clients receive encrypted blobs.
 * Without the decryption key (from URL fragment), they see only noise.
 * The server is just a "dumb pipe" for encrypted data.
 */
app.get('/api/posts', (_req: Request, res: Response<PostsResponse>) => {
  res.json({
    posts: posts,
  });
});

/**
 * GET /api/posts/:id
 *
 * Returns a single encrypted payload by ID.
 * Useful for sharing links to specific posts.
 */
app.get('/api/posts/:id', (req: Request, res: Response) => {
  const post = posts.find((p) => p.id === req.params['id']);

  if (!post) {
    res.status(404).json({
      error: 'Post not found',
    });
    return;
  }

  res.json(post);
});

/**
 * Health check endpoint.
 * Returns minimal information - no statistics that could aid analysis.
 */
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok' });
});

/**
 * Catch-all route for SPA.
 * Serves index.html for any non-API route (e.g., /post/:id#key=...).
 * The fragment (#key=...) is handled client-side.
 */
app.get('*all', (_req: Request, res: Response) => {
  res.sendFile(join(publicPath, 'index.html'));
});

// ============================================================================
// SERVER STARTUP
// ============================================================================

app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════════╗
║              BLIND IMAGEBOARD - Relay Server                     ║
╠═══════════════════════════════════════════════════════════════════╣
║  Status: RUNNING                                                  ║
║  Port: ${String(PORT).padEnd(58)}║
║                                                                   ║
║  PRIVACY MODE: ACTIVE                                             ║
║  • IP logging: DISABLED                                           ║
║  • Storage: RAM-ONLY (volatile)                                   ║
║  • Decryption capability: NONE                                    ║
║                                                                   ║
║  This server is intentionally "blind" to content.                 ║
║  It stores encrypted data but cannot read it.                     ║
╚═══════════════════════════════════════════════════════════════════╝
  `);
});

export { app };
