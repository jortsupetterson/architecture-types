// zk-iam.architecture.ts
// Architectural specification of a zero-knowledge IAM system,
// expressed as TypeScript types for clarity. This is NOT an
// implementation, but a description of required data shapes
// and dependency relationships.

// === 0. Common primitives ===

/**
 * Base64URL-encoded string used for:
 * - WebAuthn identifiers and hashes
 * - encrypted key blobs
 * - compact JWTs (pseudo-random identities)
 * Always URL-safe, typically without padding.
 */
type Base64UrlString = string;

/**
 * Logical UUID v4 string. Format validation is out of scope
 * for this architectural description.
 */
type UUIDv4 = string;

/**
 * Generic encrypted container used for every resource payload
 * (including verifiers, credentials, accounts, domain data).
 *
 * - `alg` describes the encryption algorithm (e.g. "AES-GCM").
 * - `iv`, `salt`, `tag` are cryptographic parameters as needed.
 * - `ciphertext` is an encrypted JSON document.
 *
 * IMPORTANT: The JSON inside ciphertext may contain encrypted key
 * blobs, but never raw CryptoKey material.
 */
type EncryptedEnvelope = {
  alg: string;
  iv: ArrayBuffer;
  salt?: ArrayBuffer;
  tag?: ArrayBuffer;
  ciphertext: ArrayBuffer;
};

// === 1. Authentication (WebAuthn + PRF, username-less) ===

/**
 * Server → user agent request to perform a WebAuthn assertion
 * in username-less mode. Used as the `publicKey` options for
 * `navigator.credentials.get()`.
 */
type AuthenticationRequest = {
  // Fresh, server-generated, random; must match
  // IdentityAssertion.userAgentData.challenge (after base64url).
  challenge: ArrayBuffer;

  // Relying party identifier (domain, e.g. "example.com").
  rpId: string;

  options: {
    /**
     * Username-less: authenticator must pick any suitable resident
     * credential. Therefore this is always an empty list.
     */
    allowCredentials: readonly [];

    /**
     * Always require internal user verification (PIN/biometrics).
     */
    userVerification: "required";

    /**
     * Fixed timeout policy for this system (milliseconds).
     */
    timeout: 60_000;

    /**
     * PRF is mandatory: this is how the client derives a session-bound
     * key (credentialEk) and potentially other keys.
     */
    extensions: {
      prf: {
        eval: {
          // REQUIRED: input → credentialEk (session-bound symmetric key).
          first: ArrayBuffer;
          // OPTIONAL: input for other derived keys, if needed.
          second?: ArrayBuffer;
        };
      };
    };
  };
};

/**
 * Persistent, static proof-of-identity document stored by the
 * relying party at registration time. Used later to verify
 * IdentityAssertion.
 */
type IdentityAttestation = {
  // Proof-of-identity document id, not an access credential.
  credentialId: Base64UrlString;

  // Bound relying party id (scope of this credential).
  rpId: string;

  // Public key used to verify IdentityAssertion signatures.
  publicKey: {
    alg: "ES256";
    jwk: {
      kty: "EC";
      crv: "P-256";
      x: Base64UrlString;
      y: Base64UrlString;
    };
  };

  /**
   * REQUIRED: signature counter at registration time.
   * On each authentication: newSignCount MUST be > stored signCount
   * for this credentialId; otherwise treat as replay / clone.
   */
  signCount: number;
};

/**
 * User agent → relying party proof that the authenticator performed
 * a WebAuthn assertion. Together with IdentityAttestation and
 * AuthenticationRequest this decides whether access is granted.
 */
type IdentityAssertion = {
  // Lookup key for stored public key / attestation.
  credentialId: Base64UrlString;

  userAgentData: {
    // Fixed for assertions in this flow.
    type: "webauthn.get";

    // Must equal base64url(AuthenticationRequest.challenge).
    challenge: Base64UrlString;

    // Origin of the calling page, e.g. "https://app.com".
    origin: string;
  };

  authenticatorData: {
    // SHA-256 of AuthenticationRequest.rpId.
    rpIdHash: Base64UrlString;

    // UP flag: user present.
    userPresent: boolean;

    // UV flag: user verified; MUST be true in this system.
    userVerified: boolean;

    // Monotonic signature counter (replay / clone heuristic).
    signCount: number;
  };

  // base64url(signature(authenticatorData || hash(clientDataJSON)))
  signature: Base64UrlString;
};

/**
 * Conceptual dependency for verifier access:
 * the only thing needed to locate the verifier resource
 * is the credentialId from the assertion.
 */
type VerifierAccessDependencies = IdentityAssertion["credentialId"];

/**
 * Identifier of a verifier resource, namespaced by credentialId.
 * The corresponding resource holds an IdentityAttestation.
 *
 * NOTE: This is a logical naming scheme, not a runtime guarantee.
 */
type VerifierId = `verifier:${IdentityAssertion["credentialId"]}`;

/**
 * Verifier resource content: the stored IdentityAttestation.
 * Cryptographically this is just another resource payload.
 */
type Verifier = IdentityAttestation;

/**
 * Storage of verifier resources, keyed by VerifierId.
 * Each entry is a proof document used to verify IdentityAssertion.
 */
type VerifierStorage = {
  [id: VerifierId]: Verifier;
};

/**
 * Result of the verifier pipeline:
 * - true  = assertion, attestation and request state are all valid (green light),
 * - false = at least one condition fails (no access to any credentials).
 *
 * NOTE: This is intentionally collapsed to a boolean for the
 * architectural description; real implementations may retain
 * detailed failure reasons.
 */
type AuthenticationResult = boolean;

// === 2. Credential layer (describing how to reach credentials) ===

/**
 * Identifier of a credential resource.
 * This resource is used to bridge from a credential id (obtained
 * after greenlight) to accounts and their encryption keys.
 */
type CredentialId = `credential:${UUIDv4}`;

/**
 * Conceptual dependencies required to reach a credential resource:
 * - greenlight: result of the authentication / verification pipeline,
 * - id:         the credential resource to fetch,
 * - ek:         PRF input used client-side to derive the actual
 *               session-bound decryption key (credentialEk).
 *
 * This type is descriptive; it does not represent a runtime object.
 */
type CredentialAccessDependencies = {
  greenlight: AuthenticationResult;
  id: CredentialId;
  ek: AuthenticationRequest["options"]["extensions"]["prf"]["eval"]["first"];
};

/**
 * Encrypted envelope containing credential-related JSON, such as
 * resource → account mappings and an encrypted account key.
 * Decrypted client-side with a key derived from the PRF (credentialEk).
 */
type CipherAccountCredential = EncryptedEnvelope;

/**
 * Storage of credential envelopes, keyed by CredentialId.
 * Each envelope's plaintext is a JSON structure described by `Credential`.
 */
type CredentialStorage = {
  [id: CredentialId]: CipherAccountCredential;
};

/**
 * Decrypted credential JSON structure:
 * - for each ResourceId, which AccountId "owns" that resource,
 * - ek = encoded / wrapped account encryption key, used later to
 *        decrypt account resources.
 *
 * NOTE: This is a logical description of content; there is no
 * guarantee that implementations materialize this exact shape.
 */
type ResourceId = `${string}:${UUIDv4}`; // e.g. "invoice:<uuid>", "note:<uuid>"

type AccountId = `account:${UUIDv4}`;

// type Credential
type AccountCredential = {
  [id: ResourceId]: AccountId; // "account:<uuid>"
  ek: string; // encoded/wrapped account encryption key
};

// === 3. Account layer (account is also just a resource) ===

/**
 * Conceptual dependencies required to access an account resource:
 * - id: AccountId identifying which account resource to reach,
 * - ek: account encryption key handle obtained from a Credential.
 *
 * This type describes what must be known, not a stored object.
 */
type AccountAccessDependencies = {
  id: AccountId;
  ek: AccountCredential["ek"];
};

/**
 * Encrypted account resource; decrypted with the account encryption
 * key (derived using AccountAccessDependencies.ek).
 *
 * Plaintext is logically a list of Resource objects representing
 * all account-related resources.
 */
type CipherAccount = EncryptedEnvelope;

/**
 * Storage of account envelopes, keyed by AccountId.
 * Each account is just an encrypted resource payload.
 */
type AccountStorage = {
  [id: AccountId]: CipherAccount;
};

/**
 * Decrypted account payload: a list of Resource objects this
 * account has direct knowledge of. Each Resource carries its own
 * ACL and encrypted payload.
 *
 * Architecturally: "once you can decrypt the account, you can see
 * the set of resources that form your world".
 */
type Account = Resource[];

// === 4. Pseudo-random identity for ACL evaluation ===

/**
 * JWT claims used as a pseudo-random identity handle.
 * - sub = AccountId (account resource subject),
 * - aud = service audience,
 * - iat/exp = validity window.
 *
 * This is what resources see as "who is asking" when evaluating ACL.
 */
type PseudoRandomIdentityClaims = {
  sub: AccountId; // stable across account lifespan.
  aud: string;
  iat: number;
  exp?: number;
};

/**
 * Compact JWT string encoding PseudoRandomIdentityClaims.
 * Represented as Base64UrlString for architectural purposes.
 */
type PseudoRandomIdentity = Base64UrlString;

// === 5. Resource and ACL model (uniform for all resource types) ===

/**
 * Actions that a subject can perform on a resource.
 * This is intentionally expressed as strings to mirror common
 * IAM practice (e.g. AWS IAM-style verbs).
 */
type Action =
  | "resource:read"
  | "resource:write"
  | "resource:delete"
  | "resource:share"
  | "acl:manage";

/**
 * Effect of an ACL entry.
 * - "allow" = subject is granted the listed actions (if conditions pass),
 * - "deny"  = subject is explicitly denied, even if other rules allow.
 */
type Effect = "allow" | "deny";

/**
 * Optional constraints on when an ACL entry is considered valid.
 * Evaluation semantics are left to the policy engine; the type
 * simply documents available hooks.
 */
type Condition = {
  // e.g. UNIX timestamp (ms), "not after this time".
  timeBefore?: number;
  // e.g. UNIX timestamp (ms), "not before this time".
  timeAfter?: number;
  // Optional CIDR restriction.
  ipSubnet?: string;
  // Requires resource to carry a matching tag/value in its plaintext.
  resourceTag?: string;
};

/**
 * One ACL entry: "subject X has effect Y over actions A[] under conditions C[]".
 * All ACL decisions are expressed in terms of AccountId and these rules.
 */
type ResourceAclEntry = {
  // Subject identity (account) to which this rule applies.
  subject: AccountId;
  // Allow or deny the listed actions.
  effect: Effect;
  // Which actions this rule talks about.
  actions: Action[];
  // Optional constraints evaluated by the policy engine.
  conditions?: Condition[];
};

/**
 * Resource representation:
 * - acl     = list of ACL entries (who can do what, and under which conditions),
 * - payload = encrypted content (EncryptedEnvelope).
 *
 * Verifier, Credential, Account and application-level domain objects
 * can all be modeled as Resources at the storage layer.
 */
type Resource = {
  acl: ResourceAclEntry[];
  payload: EncryptedEnvelope;
};

/**
 * Storage of resources.
 * Implementations may shard or partition storage; the outer array
 * represents an arbitrary collection of shards, each of which maps
 * ResourceId → Resource.
 */
type ResourceStorage = { [id: ResourceId]: Resource }[];
