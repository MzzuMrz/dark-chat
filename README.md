# The Blind Imageboard

**A Cypherpunk Implementation of Plausible Deniability**

*"Tengo palabras para los que quieren escuchar"*

---

## Abstract

Imagine you want to pass a note to someone in a crowded room. You write it, put it in a locked box, and hand the box to a stranger in the middle of the room. This stranger doesn't have the key—only you and your intended reader do. Later, your reader retrieves the box from the stranger and unlocks it with their copy of the key.

Now imagine someone asks the stranger what the note says. They truthfully answer: *"I don't know. I can't open the box."*

This is what we built.

The Blind Imageboard is a message board where the server—the stranger holding the boxes—cannot read any content it stores. Not because we chose not to read it, but because we *cannot*. The keys never touch our hands.

When you share a link to a post, the key travels inside the link itself, in a special place that web servers are forbidden by protocol from ever seeing. It's like writing the combination on the outside of an envelope—but only on the part that gets torn off before delivery.

The result: a space for words that only exist for those meant to receive them.

---

## Table of Contents

1. [For the Curious](#1-for-the-curious)
2. [For the Technical](#2-for-the-technical)
3. [For the Philosophical](#3-for-the-philosophical)
4. [Installation](#4-installation)
5. [Architecture](#5-architecture)
6. [Cryptographic Specification](#6-cryptographic-specification)
7. [Threat Model](#7-threat-model)
8. [References](#8-references)

---

## 1. For the Curious

### What is this?

A message board where:
- **You** can post messages that no one—not even us—can read without the key
- **You** control who gets the key by choosing who receives the link
- **The server** stores encrypted gibberish and cannot be compelled to reveal what it cannot see
- **Your identity** is a mathematical signature, not a name or email

### How does it work?

1. You write a message
2. Your browser encrypts it with a freshly generated key
3. Your browser sends the encrypted message to our server
4. The server stores it (it looks like random noise to us)
5. You get a link like: `https://example.com/post/abc123#key=xyz789`
6. Everything after the `#` (the key) **never leaves your browser**
7. When someone opens that link, their browser extracts the key and decrypts locally

The `#` is not a decoration. It's a hard boundary defined by how the web works (RFC 3986). Servers don't receive URL fragments. We didn't invent this rule—we merely exploited it.

### Why should I trust you?

You shouldn't. Trust the mathematics instead.

The encryption we use (XSalsa20-Poly1305) would require more energy than the sun will produce in its lifetime to break by brute force. The signatures (Ed25519) are the same used to verify billions of secure connections daily.

But more importantly: our server *literally cannot decrypt your messages*. Even if we wanted to. Even if someone forced us. The keys exist only in the links you share. We never see them.

---

## 2. For the Technical

### System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT SIDE                              │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────────────┐  │
│  │   Identity  │    │  Encryption  │    │  Web of Trust     │  │
│  │  Ed25519    │    │  XSalsa20    │    │  Local Filtering  │  │
│  │  Keypair    │    │  Poly1305    │    │  Block Lists      │  │
│  └─────────────┘    └──────────────┘    └───────────────────┘  │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                    { ciphertext, nonce, pubkey, signature }
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                        SERVER SIDE                               │
│                                                                  │
│     ┌─────────────────────────────────────────────────────┐     │
│     │                  BLIND STORAGE                       │     │
│     │                                                      │     │
│     │   • Stores encrypted payloads in RAM                │     │
│     │   • Verifies signatures (spam prevention)           │     │
│     │   • Cannot decrypt anything                         │     │
│     │   • No IP logging                                   │     │
│     │   • Disappears on restart                           │     │
│     │                                                      │     │
│     └─────────────────────────────────────────────────────┘     │
│                                                                  │
│     "I cannot read what I store. This is by design."            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Cryptographic Primitives

| Purpose | Algorithm | Parameters |
|---------|-----------|------------|
| Symmetric Encryption | XSalsa20-Poly1305 | 256-bit key, 192-bit nonce |
| Digital Signatures | Ed25519 | 256-bit public key, 512-bit signature |
| Random Generation | `crypto.getRandomValues()` | CSPRNG |

### The URL Fragment Exploit

This is the core insight that makes the system work.

Per RFC 3986 §3.5:
> The fragment identifier component of a URI [...] is not a part of the URI scheme. [...] The fragment identifier is separated from the rest of the URI prior to a dereference.

Translation: **browsers strip everything after `#` before sending requests to servers**.

We place the symmetric decryption key in the fragment:
```
https://blind.example/post/a1b2c3#key=SGVsbG8gV29ybGQ
                                  ↑
                          Server never sees this
```

This isn't a trick. This isn't obscurity. This is the specification being used exactly as intended, for a purpose that happens to enable cryptographic privacy.

### Data Flow

**Publishing:**
```
plaintext → (generate K, N) → encrypt(plaintext, K, N) → C
identity.privateKey → sign(C) → σ
POST { C, N, pubkey, σ } → server
return URL + #key=base64(K)
```

**Reading:**
```
URL → extract fragment → K = base64decode(fragment)
GET /post/:id → { C, N, pubkey, σ }
verify(C, σ, pubkey) → boolean
decrypt(C, K, N) → plaintext
```

### API Specification

```
POST /api/publish
  Request:  { ciphertext, nonce, authorPublicKey, signature }
  Response: { success: true, id: string } | { success: false, error: string }

GET /api/posts
  Response: { posts: EncryptedPayload[] }

GET /api/posts/:id
  Response: EncryptedPayload | 404

GET /api/health
  Response: { status: "ok" }
```

### Storage Model

**In-memory only.** No database. No disk writes. No persistence.

```typescript
const posts: EncryptedPayload[] = [];  // Dies with the process
const MAX_POSTS = 1000;                 // FIFO eviction
```

This is not a limitation—it's a feature. When the server restarts, all data ceases to exist. There is nothing to subpoena. Nothing to forensically recover. The operator can truthfully state under oath: *"That data no longer exists."*

---

## 3. For the Philosophical

### On the Nature of Privacy

Privacy is not secrecy. Privacy is selective disclosure.

A secret is something you tell no one. Privacy is something you choose who to share with. The person you love knows things your employer doesn't. Your doctor knows things your friends don't. This is not deception—this is the architecture of human relationships.

When systems demand transparency from individuals while offering opacity for themselves, the power asymmetry is not accidental. It is architectural.

We built this system because we believe in inverting that architecture.

### The Server's Blindness

Traditional servers are omniscient within their domain. They see everything. They log everything. Even when they promise not to, the capability exists. The temptation exists. The legal compulsion can exist.

Our server is blind by construction, not by policy.

We do not promise not to read your messages—we demonstrate we cannot. We do not ask for trust—we eliminate the need for it. The cryptographic guarantees are not our assertion; they are mathematical facts verifiable by anyone who cares to look.

*"Cypherpunks write code."* — Eric Hughes, 1993

We are not asking for privacy rights. We are not lobbying for better policies. We are writing systems that make surveillance technically infeasible, regardless of what laws say it's permissible.

### Plausible Deniability

The term comes from political science, but the concept has deep cryptographic applications.

Consider an operator of this server under legal pressure:

> **Q:** What messages are stored on your server?
> **A:** I don't know. They're encrypted with keys I've never possessed.
>
> **Q:** Who posted the content?
> **A:** I have public keys, which are pseudonymous. They're not linked to identities I can provide.
>
> **Q:** Do you have logs of who accessed what?
> **A:** No. We don't log IPs. This is documented in our source code.
>
> **Q:** If we seized your server, what would we find?
> **A:** Encrypted data that you cannot decrypt, timestamps, and public keys. The decryption keys exist only in URLs shared between users. We have never seen them.

This is not evasion. This is truthful testimony about a system designed to make these answers the only possible answers.

### The Ethics of Enabling

*"But this could be used for harmful purposes."*

Yes. So can mathematics. So can language. So can fire.

We do not control what people write in encrypted messages any more than locksmiths control what people store in safes. The capability for private communication predates us and will outlive us. We merely make it more accessible.

Those who argue for backdoors in encryption argue for a mathematical impossibility: a door that only opens for "good" actors. No such door can exist. A backdoor for governments is a backdoor for every adversary capable of finding or stealing that access—and history shows they always do.

We choose to build systems that assume adversarial conditions because adversarial conditions are the eventual norm. The question is not whether secure communication will exist, but whether it will exist only for the technically sophisticated or for everyone.

### On Identity

In this system, your identity is a 32-byte public key. It is not your name. Not your email. Not your government-assigned number. It is a mathematical object that proves you are consistent across messages.

You can generate a new identity with a single function call. You can have many identities. You can discard them. Each one proves only that whoever controls the corresponding private key authored a particular message.

This is pseudonymity: persistent identity without attribution to physical personhood.

The Web of Trust features allow users to filter by public key—to accumulate trust in consistent pseudonymous actors without ever knowing their legal names. Reputation built on demonstrated behavior, not claimed credentials.

This is not a rejection of identity. It is a different architecture for it.

### Why "Blind"?

We chose this name because it captures the essential property: the server does not see.

In the legend of Lady Justice, blindness represents impartiality—judgment without prejudice. Our blindness is different. It represents *incapacity*—we cannot judge because we cannot perceive.

This is a stronger guarantee. Impartiality can be corrupted. Incapacity cannot.

The server is not a neutral arbiter. It is a dumb pipe. It moves bytes it cannot interpret, stores ciphertext it cannot decrypt, verifies signatures it cannot contextualize. Its blindness is not a virtue—it is a structural property.

### Closing Words

*"The Net interprets censorship as damage and routes around it."* — John Gilmore

We write these systems not because we are optimistic about human nature but because we are realistic about power structures. Systems that depend on the benevolence of the powerful are systems that will eventually fail.

Cryptographic privacy doesn't ask permission. It doesn't depend on policy. It is math that anyone can verify and no one can override.

For those who understand why this matters: welcome.
For those who wonder why anyone would build this: may you never need it.
For those who would prevent such systems: you are already too late.

*Tengo palabras para los que quieren escuchar.*

---

## 4. Installation

### Requirements
- Node.js 18+
- npm

### Quick Start

```bash
# Clone
git clone <repository-url>
cd darkchat

# Install dependencies
npm install

# Development mode
npm run dev

# Production build
npm run build
npm start

# Run tests
npm test
```

Server runs on `http://localhost:3000` by default.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server listening port |

### Production Considerations

The current implementation is a demonstration. For production deployment, consider:

1. **Tor Hidden Service**: Run behind `.onion` for network-level anonymity
2. **Rate Limiting**: Prevent abuse without logging (use proof-of-work challenges)
3. **Encrypted Disk Storage**: If persistence is needed, use FDE with secure deletion
4. **Random Delays**: Add jitter to obscure timing correlations
5. **Load Balancing**: Multiple blind servers with no shared state

---

## 5. Architecture

### File Structure

```
darkchat/
├── server/
│   └── index.ts          # Express server, validation, blind storage
├── client/
│   └── cryptoLogic.ts    # Encryption, decryption, identity, Web of Trust
├── shared/
│   └── types.ts          # TypeScript interfaces
├── public/
│   └── index.html        # SPA frontend
├── test/
│   └── integration.ts    # Comprehensive test suite
├── package.json
└── tsconfig.json
```

### Component Responsibilities

| Component | Responsibility | Touches Plaintext? |
|-----------|----------------|-------------------|
| `server/index.ts` | Store/retrieve encrypted payloads, verify signatures | **Never** |
| `client/cryptoLogic.ts` | All cryptographic operations | **Yes** (client-side only) |
| `shared/types.ts` | Type definitions | N/A |
| `public/index.html` | User interface, crypto integration | **Yes** (in browser only) |

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                     TRUSTED ZONE                             │
│                  (User's Browser)                            │
│                                                              │
│   • Plaintext exists here                                   │
│   • Private keys stored here (localStorage)                 │
│   • Encryption/decryption happens here                      │
│   • Web of Trust filtering happens here                     │
│                                                              │
└──────────────────────────┬──────────────────────────────────┘
                           │
          ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─
              TRUST BOUNDARY (HTTPS + URL Fragment)
          ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                    UNTRUSTED ZONE                            │
│                      (Server)                                │
│                                                              │
│   • Only sees ciphertext                                    │
│   • Never sees symmetric keys                               │
│   • Cannot decrypt stored content                           │
│   • Can verify signatures (spam prevention)                 │
│   • Minimal metadata (timestamp, public key)                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. Cryptographic Specification

### Symmetric Encryption

**Algorithm**: XSalsa20-Poly1305 (via TweetNaCl.js `secretbox`)

```
K ← random(32 bytes)     // Key
N ← random(24 bytes)     // Nonce
C ← XSalsa20-Poly1305.seal(plaintext, N, K)
```

**Properties**:
- Authenticated encryption (AEAD)
- 256-bit security level
- Poly1305 MAC prevents tampering
- Random nonce ensures semantic security

### Digital Signatures

**Algorithm**: Ed25519 (via TweetNaCl.js `sign`)

```
(pk, sk) ← Ed25519.keypair()    // 32-byte public, 64-byte private
σ ← Ed25519.sign.detached(C, sk)  // Sign ciphertext
valid ← Ed25519.verify(C, σ, pk)  // Verify signature
```

**Properties**:
- 128-bit security level
- Fast verification
- Small signatures (64 bytes)
- Deterministic (same input → same signature)

### Key Derivation

No KDF is used. Each symmetric key is:
- Generated fresh per post
- Cryptographically random
- Never reused
- Never derived from passwords

### Security Guarantees

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| Confidentiality | Only key holders can read | XSalsa20-Poly1305 |
| Integrity | Tampering is detected | Poly1305 MAC |
| Authenticity | Author is verified | Ed25519 signature |
| Forward Secrecy | Per-post keys | No key reuse |
| Plausible Deniability | Server cannot decrypt | Keys in URL fragment |

---

## 7. Threat Model

### In Scope

| Threat | Mitigation |
|--------|------------|
| Server operator reads content | Cannot—no access to symmetric keys |
| Law enforcement seizure | Only obtains encrypted data and public keys |
| Network eavesdropping | TLS + keys in fragment (never transmitted) |
| Signature forgery | Ed25519 prevents impersonation |
| Content tampering | Poly1305 MAC detects modification |
| User tracking by server | No IP logging, minimal metadata |

### Out of Scope

| Threat | Notes |
|--------|-------|
| Client-side compromise | If browser is compromised, all keys are exposed |
| Key loss | If URL fragment is lost, content is unrecoverable |
| Traffic analysis | Timing/size correlation not addressed |
| Quantum computing | Ed25519 and XSalsa20 are not post-quantum |
| Metadata analysis | Timestamps and public keys are visible |
| Endpoint compromise | Recipient's device security is their responsibility |

### Operational Security Notes

- **Key Sharing**: The URL fragment is the key. Share it only through secure channels.
- **Identity Management**: Generate new keypairs for unlinkability.
- **Session Security**: Clear localStorage to delete identity.
- **Network Privacy**: Use Tor for network-level anonymity (recommended).

---

## 8. References

### Cryptographic Standards

1. Bernstein, D.J. (2008). *The Salsa20 family of stream ciphers*. New Stream Cipher Designs.
2. Bernstein, D.J., et al. (2012). *High-speed high-security signatures*. Journal of Cryptographic Engineering.
3. Bernstein, D.J. (2005). *The Poly1305-AES message-authentication code*. FSE 2005.

### Implementation

4. TweetNaCl.js: https://tweetnacl.js.org/
5. RFC 3986 - *Uniform Resource Identifier (URI): Generic Syntax*

### Philosophy

6. Hughes, E. (1993). *A Cypherpunk's Manifesto*.
7. May, T.C. (1992). *The Crypto Anarchist Manifesto*.
8. Chaum, D. (1985). *Security without identification: Transaction systems to make Big Brother obsolete*.

---

## License

MIT

---

## Colophon

Written with the understanding that privacy is not a feature—it is a right.
Built with the belief that mathematics is more reliable than policy.
Released with the hope that those who need it will find it.

*"Privacy is not about having something to hide. Privacy is about having something to protect."*

---

**Repository**: darkchat
**Type**: Blind Relay Imageboard with Plausible Deniability
**Status**: Experimental / Demonstration
**Cryptography**: XSalsa20-Poly1305 + Ed25519 via TweetNaCl.js
# dark-chat
