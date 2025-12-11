// zk-iam.architecture.ts
// Architectural specification of a zero-knowledge IAM system.
// This file uses TypeScript types as a descriptive language for
// data shapes, invariants and dependency relationships. It is NOT
// an implementation and MUST NOT be treated as one.
//
// -----------------------------------------------------------------------------
// SCOPE / PURPOSE / GOALS
// -----------------------------------------------------------------------------
// Purpose:
//   Describe a passkey-based (WebAuthn + PRF) identity and access management
//   system in which the server never learns decryption keys for any resource,
//   account or credential payload. All sensitive content is opaque ciphertext.
//
// Scope:
//   - How authenticators prove possession of a resident credential
//     (IdentityAssertion / IdentityAttestation / AuthenticationRequest).
//   - How that proof is turned into access to encrypted credentials,
//     accounts and resources (Verifier → Credential → Account → Resource).
//   - How subjects are represented as pseudo-random identities (JWT-style)
//     for ACL evaluation, without exposing stable user identifiers.
//   - How access decisions are made (canRead/Write/Delete/Share/ManageAcl)
//     given tokens, ACL entries and client-derived key material.
//   - Architectural invariants for rkm (resource key material) and identity
//     multipath, independent of UX details (e.g. recovery flows).
//
// Non-goals (explicitly out of scope here):
//   - Concrete UX flows (screen design, UI steps).
//   - Concrete recovery mechanisms (email, backup codes, etc.).
//   - Specific cryptographic parameter choices beyond what is needed
//     to state invariants (e.g. key sizes, KDF iteration counts).
//   - Surveillance, analytics, behavioural tracking or auditing.
//     This system is designed to operate without any of that.
//
// Architectural stance on multipath identity and recovery:
//   - The stable subject is AccountId. Multiple independent authenticators
//     (WebAuthn credentials) MAY point to the same AccountId.
//   - Optional recovery anchors (e.g. email-hash → AccountId) MAY be added
//     by implementations, but any such mapping MUST itself be represented
//     as a Resource subject to ACL, with the same zero-knowledge properties.
//   - Whether recovery exists and which anchors are offered is a UX/product
//     decision. The architecture remains neutral (no required anchors).
//
// Architectural stance on rkm (resource key material):
//   - rkm is always carried as opaque, wrapped or encoded material.
//   - rkm MUST be derived so that:
//       * It is unlinkable across independent WebAuthn credentials.
//       * It is bound to the authenticator path that derived it
//         (no “unscoped” rkm that works everywhere).
//       * It does not allow cross-resource inference when reused
//         as input to further derivations.
//   - The server never sees the raw keys derived from rkm; it only
//     sees opaque rkm blobs, encrypted envelopes and public keys
//     needed for signature verification.
//
// -----------------------------------------------------------------------------
// === 0. Common primitives ===
// -----------------------------------------------------------------------------

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
 * - `ciphertext` is an encrypted document.
 *
 * The document inside `ciphertext` may contain key material,
 * application data, or any other structure. This does not affect
 * the security model: as long as the key is unknown to the server,
 * the ciphertext is opaque and cannot be decrypted or inspected.
 */
type EncryptedEnvelope = {
  alg: string;
  iv: ArrayBuffer;
  salt?: ArrayBuffer;
  tag?: ArrayBuffer;
  ciphertext: ArrayBuffer;
};

// -----------------------------------------------------------------------------
// === 1. Authentication (WebAuthn + PRF, username-less) ===
// -----------------------------------------------------------------------------

/**
 * Server → user agent request to perform a WebAuthn assertion
 * in username-less mode. Used as the `publicKey` options for
 * `navigator.credentials.get()`.
 */
type AuthenticationRequest = {
  /**
   * Fresh, server-generated, random challenge.
   * Must match IdentityAssertion.userAgentData.challenge
   * after Base64URL encoding.
   */
  challenge: ArrayBuffer;

  /**
   * Relying party identifier (domain, e.g. "example.com").
   * This is what authenticators bind to in rpIdHash.
   */
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
     * PRF is mandatory: this is how the client derives session-bound
     * key material (credential resource key) and potentially other keys.
     *
     * Architectural invariants:
     * - The PRF output used as rkm MUST be unique to the authenticator
     *   path that produced it (bound to the chosen credential and rpId).
     * - Different WebAuthn credentials for the same AccountId MUST NOT
     *   generate linkable rkm values.
     */
    extensions: {
      prf: {
        eval: {
          /**
           * REQUIRED: input whose PRF output becomes credential-level
           * resource key material (session-bound rkm).
           */
          first: ArrayBuffer;
          /**
           * OPTIONAL: input for other derived keys, if needed by
           * higher-level protocols.
           */
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
  /**
   * Proof-of-identity document id, not an access credential.
   * This is the WebAuthn credentialId as a Base64URL string.
   */
  credentialId: Base64UrlString;

  /**
   * Bound relying party id (scope of this credential).
   * Must match AuthenticationRequest.rpId (after rpIdHash).
   */
  rpId: string;

  /**
   * Public key used to verify IdentityAssertion signatures.
   */
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
  /**
   * Lookup key for stored public key / attestation.
   * This MUST match IdentityAttestation.credentialId.
   */
  credentialId: Base64UrlString;

  userAgentData: {
    /**
     * Fixed for assertions in this flow.
     */
    type: "webauthn.get";

    /**
     * Must equal base64url(AuthenticationRequest.challenge).
     */
    challenge: Base64UrlString;

    /**
     * Origin of the calling page, e.g. "https://app.com".
     * The verifier MUST ensure it is within the expected set.
     */
    origin: string;
  };

  authenticatorData: {
    /**
     * SHA-256 of AuthenticationRequest.rpId.
     * This binds the assertion to the relying party.
     */
    rpIdHash: Base64UrlString;

    /**
     * UP flag: user present.
     */
    userPresent: boolean;

    /**
     * UV flag: user verified; MUST be true in this system.
     */
    userVerified: boolean;

    /**
     * Monotonic signature counter (replay / clone heuristic).
     */
    signCount: number;
  };

  /**
   * Base64URL of signature(authenticatorData || hash(clientDataJSON)).
   * Verified using IdentityAttestation.publicKey.
   */
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
 * Storage MAY reside in cloud infrastructure, local storage, or both.
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

// -----------------------------------------------------------------------------
// === 2. Credential layer (describing how to reach credentials) ===
// -----------------------------------------------------------------------------

/**
 * Stable identity of an account resource.
 * This is the subject used in pseudo-random identity tokens (sub).
 */
type AccountId = `account:${UUIDv4}`;

/**
 * Identifier of a credential resource.
 * This resource is used to bridge from a WebAuthn credential
 * (after green light) to accounts and their encryption keys.
 */
type CredentialId = `credential:${UUIDv4}`;

/**
 * Conceptual dependencies required to reach a credential resource:
 * - greenlight: result of the authentication / verification pipeline,
 * - id:         the credential resource to fetch,
 * - rkm:        PRF-derived key material used client-side to derive the
 *               actual session-bound credential key.
 *
 * This type is descriptive; it does not represent a runtime object.
 *
 * Architectural invariants:
 * - greenlight MUST be true before any credential access is honoured.
 * - rkm MUST be derived from the PRF output bound to the successful
 *   IdentityAssertion (no reuse from other contexts).
 */
type CredentialAccessDependencies = {
  greenlight: AuthenticationResult;
  id: CredentialId;
  rkm: AuthenticationRequest["options"]["extensions"]["prf"]["eval"]["first"];
};

/**
 * Encrypted envelope containing credential-related JSON, such as
 * resource → account mappings and an encrypted account key.
 * Decrypted client-side with key material derived from the PRF.
 */
type CipherAccountCredential = EncryptedEnvelope;

/**
 * Storage of credential envelopes, keyed by CredentialId.
 * Each envelope's plaintext is a JSON structure described by `AccountCredential`.
 * Storage MAY be persisted in the cloud, offline (client-only), or both.
 */
type CredentialStorage = {
  [id: CredentialId]: CipherAccountCredential;
};

/**
 * Decrypted credential JSON structure:
 * - for each resource identifier (see ResourceId), which AccountId "owns" it,
 * - rkm = encoded / wrapped account resource key material, used later to
 *         derive account-level cryptographic keys.
 *
 * Architectural invariants:
 * - The mapping "resource-like id" → AccountId expresses *reachability*,
 *   not visibility; ACL still governs what is actually allowed.
 * - AccountCredential.rkm is opaque wrapped material; the server
 *   MUST NOT be able to unwrap it.
 *
 * NOTE:
 * - Keys are typed as `string` here but are logically ResourceId.
 *   ResourceId is defined in the resource section.
 */
type AccountCredential = {
  [id: string]: AccountId; // logically: ResourceId → AccountId
  rkm: Base64UrlString; // encoded/wrapped account key material
};

// -----------------------------------------------------------------------------
// === 3. Account layer (account holds resource credentials) ===
// -----------------------------------------------------------------------------

/**
 * Conceptual dependencies required to access an account resource:
 * - id:  AccountId identifying which account resource to reach,
 * - rkm: account key material handle obtained from a Credential.
 *
 * This type describes what must be known, not a stored object.
 *
 * Architectural invariants:
 * - rkm here is still opaque to the server; derivation of actual
 *   keys happens only on the client.
 */
type AccountAccessDependencies = {
  id: AccountId;
  rkm: AccountCredential["rkm"];
};

/**
 * Encrypted account resource; decrypted with the account key material
 * (derived using AccountAccessDependencies.rkm).
 *
 * Plaintext is logically a list of ResourceCredential objects that
 * describe which resources this account can reach and how to derive
 * their resource key material.
 */
type CipherAccount = EncryptedEnvelope;

/**
 * Storage of account envelopes, keyed by AccountId.
 * Each account is just an encrypted resource payload.
 * Storage MAY be offline (client device), in the cloud, or synchronized between both.
 */
type AccountStorage = {
  [id: AccountId]: CipherAccount;
};

/**
 * A credential handle for a single resource:
 * - id  = ResourceId (defined in the resource section),
 * - rkm = wrapped/encoded resource key material for that resource.
 *
 * Architectural invariants:
 * - rkm is per-resource and opaque; actual keys are derived only on
 *   the client and are never exposed to the server.
 */
type ResourceCredential = {
  id: ResourceId;
  rkm: Base64UrlString;
};

/**
 * Decrypted account payload: a list of ResourceCredential objects this
 * account has direct knowledge of. Each ResourceCredential gives:
 *   - the resource identifier,
 *   - the wrapped resource key material for that resource.
 *
 * Architecturally: "once you can decrypt the account, you can see
 * the set of resource credentials that form your world". Whether any
 * particular resource can actually be read or written is still
 * governed by ACL and the canDo predicates.
 */
type Account = ResourceCredential[];

// -----------------------------------------------------------------------------
// === 4. Pseudo-random identity for ACL evaluation ===
// -----------------------------------------------------------------------------

/**
 * JWT claims used as a pseudo-random identity handle.
 * - sub = AccountId (account resource subject),
 * - aud = service audience,
 * - iat/exp = validity window.
 *
 * This is what resources see as "who is asking" when evaluating ACL.
 * It deliberately hides the underlying WebAuthn credential structure.
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
 *
 * Architectural invariant:
 * - Tokens MUST be unlinkable to any particular WebAuthn credential;
 *   they represent accounts, not devices.
 */
type PseudoRandomIdentity = Base64UrlString;

// -----------------------------------------------------------------------------
// === 5. Resource and ACL model (uniform for all resource types) ===
// -----------------------------------------------------------------------------

/**
 * Resource identifiers.
 * Example values:
 *   "invoice:<uuid>", "note:<uuid>", "account:<uuid>"
 *
 * NOTE:
 * - This type is referenced earlier by AccountCredential (as string keys)
 *   and by ResourceCredential.id.
 */
type ResourceId = `${string}:${UUIDv4}`;

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
  /**
   * e.g. UNIX timestamp (ms), "not after this time".
   */
  timeBefore?: number;

  /**
   * e.g. UNIX timestamp (ms), "not before this time".
   */
  timeAfter?: number;
};

/**
 * One ACL entry: "subject X has effect Y over actions A[] under conditions C[]".
 * All ACL decisions are expressed in terms of AccountId and these rules.
 */
type ResourceAclEntry = {
  /**
   * Subject identity (account) to which this rule applies.
   */
  subject: AccountId;

  /**
   * Allow or deny the listed actions.
   */
  effect: Effect;

  /**
   * Which actions this rule talks about.
   */
  actions: Action[];

  /**
   * Optional constraints evaluated by the policy engine.
   */
  conditions?: Condition[];
};

/**
 * Conceptual view of how resource key material is used on the client.
 * This is NOT stored; it represents derived runtime keys:
 * - symmetricKey: used to encrypt/decrypt the resource payload.
 * - signingKeyPair: used to sign requests; server verifies using publicKey.
 *
 * Architectural invariants:
 * - The privateKey MUST never leave the client.
 * - The server MAY store the corresponding publicKey, but MUST NOT
 *   be able to use it to decrypt any payloads.
 */
type ResourceKeyDerivations = {
  symmetricKey: CryptoKey; // AES-GCM or similar, derived from rkm
  signingKeyPair: {
    publicKey: CryptoKey; // MAY be stored alongside the resource/ACL
    privateKey: CryptoKey; // lives only on the client
  };
};

/**
 * Conceptual dependencies required to access a resource:
 * - id:       The unique identifier of the resource to be accessed.
 * - token:    A compact pseudo-random identity (e.g. JWT) signed by the server,
 *             which must match an ACL entry granting permission for the requested action.
 * - rkm:      Resource key material (wrapped/encoded). On the client this MUST be
 *             transformed into:
 *             - a symmetricKey used to decrypt/encrypt payloads, and
 *             - a signingKeyPair whose privateKey is used to sign the request.
 *
 * Cloud API behaviour:
 * - The server will:
 *   - evaluate the token against the ACL (subject/actions/conditions),
 *   - verify that the request is signed with the publicKey corresponding to
 *     the resource’s key material,
 *   - only then accept "read" (returning encrypted payload) or "write"
 *     (storing a new encrypted payload).
 *
 * NOTE:
 * - Having an ACL match without a valid signature is rejected.
 * - Having valid key-derived signatures without an ACL match is rejected.
 * - Only the client ever sees/derives the symmetricKey and privateKey;
 *   the server sees at most the publicKey and opaque rkm blobs.
 *
 * Architectural invariants:
 * - rkm MUST be specific to the resource context; even if the same
 *   wrapped blob appears in multiple places, its derivations MUST NOT
 *   allow cross-resource plaintext linkage at the server.
 */
type ResourceAccessDependencies = {
  id: ResourceId;
  token: PseudoRandomIdentity;
  rkm: Base64UrlString;
};

/**
 * Resource representation:
 * - acl     = list of ACL entries (who can do what, and under which conditions),
 * - payload = encrypted content (EncryptedEnvelope).
 *
 * Verifier, Credential, Account and application-level domain objects
 * can all be modeled as Resources at the storage layer.
 *
 * The authoritative ACL state is maintained on the server/cloud.
 * Clients MAY keep cached read-only projections for offline UX, but these
 * do not override the server-side ACL when reconnecting.
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
 *
 * Resource payloads MAY be stored in the cloud, offline on clients,
 * or replicated between both; ACL enforcement, however, is evaluated
 * against the server/cloud view when online.
 */
type ResourceStorage = { [id: ResourceId]: Resource }[];

// -----------------------------------------------------------------------------
// === 6. Conceptual capability predicates (canDo helpers) ===
// -----------------------------------------------------------------------------

/**
 * Conceptual predicate: can the caller READ this resource?
 *
 * Requirements (all must hold):
 * - token.sub identifies an AccountId that appears in an ACL entry
 *   with effect "allow" for "resource:read" and whose conditions pass.
 * - no ACL entry with effect "deny" for "resource:read" matching the
 *   same subject and conditions exists.
 * - the request is signed with a key derived from rkm, and the server
 *   can verify this signature using the stored publicKey for the resource.
 */
declare function canReadResource(
  resource: Resource,
  deps: ResourceAccessDependencies
): boolean;

/**
 * Conceptual predicate: can the caller WRITE (create/update) this resource?
 *
 * Requirements (all must hold):
 * - token.sub identifies an AccountId that appears in an ACL entry
 *   with effect "allow" for "resource:write" and whose conditions pass.
 * - no higher-priority or matching "deny" rule for "resource:write"
 *   applies to the same subject and conditions.
 * - the new payload is encrypted client-side using a symmetric key
 *   derived from rkm.
 * - the write request (including any integrity hash of the ciphertext)
 *   is signed with a key derived from rkm, and the server verifies
 *   this signature using the corresponding publicKey.
 */
declare function canWriteResource(
  resource: Resource,
  deps: ResourceAccessDependencies
): boolean;

/**
 * Conceptual predicate: can the caller DELETE this resource?
 *
 * Requirements (all must hold):
 * - token.sub has an "allow" ACL entry for "resource:delete" whose
 *   conditions pass, and no conflicting "deny" entry overrides it.
 * - the delete request is signed with a key derived from rkm, and
 *   the server verifies this signature using the corresponding publicKey.
 */
declare function canDeleteResource(
  resource: Resource,
  deps: ResourceAccessDependencies
): boolean;

/**
 * Conceptual predicate: can the caller SHARE this resource (grant
 * or propagate access to other accounts)?
 *
 * Requirements (all must hold):
 * - token.sub has an "allow" ACL entry for "resource:share" and/or
 *   "acl:manage" whose conditions pass.
 * - no matching "deny" entry for "resource:share" or "acl:manage"
 *   applies to the same subject and conditions.
 * - the share/update operation (including any ACL changes to be applied)
 *   is signed with a key derived from rkm, and verified by the server.
 */
declare function canShareResource(
  resource: Resource,
  deps: ResourceAccessDependencies
): boolean;

/**
 * Conceptual predicate: can the caller MANAGE the ACL of this resource?
 *
 * Requirements (all must hold):
 * - token.sub has an "allow" ACL entry for "acl:manage" whose
 *   conditions pass.
 * - no matching "deny" entry for "acl:manage" applies to the same
 *   subject and conditions.
 * - the ACL mutation request is signed with a key derived from rkm,
 *   and the server verifies this signature using the corresponding publicKey.
 */
declare function canManageAcl(
  resource: Resource,
  deps: ResourceAccessDependencies
): boolean;
