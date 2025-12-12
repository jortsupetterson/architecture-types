// zk-iam.architecture.ts
// Architectural specification of a zero-knowledge Identity and Access
// Management (IAM) system.
//
// This document uses TypeScript types as a descriptive language for
// data shapes, invariants, and dependency relationships.
// It is NOT an implementation and MUST NOT be treated as one.

// ============================================================================
// 0. SPEC METADATA
// ============================================================================

type SpecMetadata = {
  name: "zk-iam";
  version: `${number}.${number}.${number}`;
  status: "draft" | "stable" | "deprecated";
  editedAt: `${number}-${number}-${number}`;
  authorship: "human-led" | "ai-assisted" | "ai-generated";
};

const specMeta: SpecMetadata = {
  name: "zk-iam",
  version: "0.1.0",
  status: "draft",
  editedAt: "2025-12-12",
  authorship: "ai-assisted",
};

// ============================================================================
// 1. PURPOSE / SCOPE / NON-GOALS
// ============================================================================

type SpecPurpose = {
  purpose: string;
  scope: readonly string[];
  nonGoals: readonly string[];
};

const specPurpose: SpecPurpose = {
  purpose:
    "Describe a passkey-based (WebAuthn + PRF) identity and access management system in which the server never learns decryption keys for any credential, account, or resource payload. All sensitive content is opaque ciphertext to the server.",
  scope: [
    "How authenticators prove possession of a resident credential using WebAuthn assertions.",
    "How successful authentication unlocks encrypted credentials, accounts, and resources (Verifier → Credential → Account → Resource).",
    "How access control is evaluated using pseudorandom subject identifiers without exposing real-world or device identifiers.",
    "How authorization requires both server-side policy (ACL) and client-side proof of key possession.",
    "Architectural invariants for resource key material (rkm) and multipath identity, independent of UX or recovery design.",
  ] as const,
  nonGoals: [
    "User interface or user experience flows.",
    "Concrete recovery mechanisms (email, backup codes, social recovery, etc.).",
    "Specific cryptographic parameter choices (algorithms, key sizes, KDF settings).",
    "Telemetry, analytics, surveillance, or behavioral profiling.",
    "Operating system or hardware security guarantees.",
  ] as const,
};

// ============================================================================
// 2. DEFINITIONS
// ============================================================================
//
// Pseudorandom subject identity:
//   - ACL subjects are opaque identifiers (AccountId).
//   - These identifiers are stable within the system but have no
//     human-meaningful or device-meaningful interpretation.
//   - This is the minimum information required for authorization.
//
// Zero-knowledge property:
//   - The server never learns plaintext payloads.
//   - The server never learns decryption keys.
//   - The server MAY see opaque ciphertext, opaque wrapped key material,
//     public keys for signature verification, and ACL policy state.

// ============================================================================
// 3. TRUST BOUNDARIES
// ============================================================================

type TrustZone =
  | "client-runtime"
  | "client-storage"
  | "network"
  | "server-runtime"
  | "server-storage";

type TrustBoundary = {
  plaintextAllowedIn: readonly TrustZone[];
  plaintextForbiddenIn: readonly TrustZone[];
  decryptionKeysForbiddenIn: readonly TrustZone[];
  notes: readonly string[];
};

const trustBoundary: TrustBoundary = {
  plaintextAllowedIn: ["client-runtime"] as const,
  plaintextForbiddenIn: [
    "client-storage",
    "network",
    "server-runtime",
    "server-storage",
  ] as const,
  decryptionKeysForbiddenIn: [
    "client-storage",
    "network",
    "server-runtime",
    "server-storage",
  ] as const,
  notes: [
    "The client runtime is the only location where plaintext and derived private keys may exist.",
    "Client storage is assumed readable by an attacker and therefore contains only encrypted material.",
    "The server enforces policy and routing but cannot decrypt any payloads.",
  ] as const,
};

// ============================================================================
// 4. THREAT MODEL
// ============================================================================

type AttackerCapability =
  | "read-server-storage"
  | "write-server-storage"
  | "observe-network"
  | "replay-network"
  | "malicious-client"
  | "malicious-server";

type ThreatModel = {
  assumed: readonly AttackerCapability[];
  outOfScope: readonly string[];
  goals: readonly string[];
};

const threatModel: ThreatModel = {
  assumed: [
    "read-server-storage",
    "write-server-storage",
    "observe-network",
    "replay-network",
    "malicious-client",
    "malicious-server",
  ] as const,
  outOfScope: [
    "Operating system compromise.",
    "Hardware compromise.",
    "Browser engine compromise.",
    "User-controlled runtime misuse (Self-XSS).",
  ] as const,
  goals: [
    "Server compromise does not reveal plaintext data.",
    "Network observation does not reveal plaintext data or decryption keys.",
    "Authorization cannot be bypassed without both ACL permission and key possession.",
    "Multiple authenticators can access the same account without revealing linkage at the server.",
  ] as const,
};

// ============================================================================
// 5. COMMON PRIMITIVES
// ============================================================================

type Base64UrlString = string;
type UUIDv4 = string;

type EncryptedEnvelope = {
  alg: string;
  iv: ArrayBuffer;
  salt?: ArrayBuffer;
  tag?: ArrayBuffer;
  ciphertext: ArrayBuffer;
};

// ============================================================================
// 6. AUTHENTICATION (WEB AUTHN + PRF)
// ============================================================================

type AuthenticationRequest = {
  challenge: ArrayBuffer;
  rpId: string;
  options: {
    allowCredentials: readonly [];
    userVerification: "required";
    timeout: 60_000;
    extensions: {
      prf: {
        eval: {
          first: ArrayBuffer;
          second?: ArrayBuffer;
        };
      };
    };
  };
};

type IdentityAttestation = {
  credentialId: Base64UrlString;
  rpId: string;
  publicKey: {
    alg: "ES256";
    jwk: {
      kty: "EC";
      crv: "P-256";
      x: Base64UrlString;
      y: Base64UrlString;
    };
  };
  signCount: number;
};

type IdentityAssertion = {
  credentialId: Base64UrlString;
  userAgentData: {
    type: "webauthn.get";
    challenge: Base64UrlString;
    origin: string;
  };
  authenticatorData: {
    rpIdHash: Base64UrlString;
    userPresent: boolean;
    userVerified: boolean;
    signCount: number;
  };
  signature: Base64UrlString;
};

type VerifierId = `verifier:${IdentityAssertion["credentialId"]}`;
type Verifier = IdentityAttestation;

type VerifierStorage = {
  [id: VerifierId]: Verifier;
};

type AuthenticationResult = boolean;

// ============================================================================
// 7. CREDENTIAL LAYER
// ============================================================================

type AccountId = `account:${UUIDv4}`;
type CredentialId = `credential:${UUIDv4}`;

type CredentialAccessDependencies = {
  greenlight: AuthenticationResult;
  id: CredentialId;
  rkm: AuthenticationRequest["options"]["extensions"]["prf"]["eval"]["first"];
};

type CipherAccountCredential = EncryptedEnvelope;

type CredentialStorage = {
  [id: CredentialId]: CipherAccountCredential;
};

type AccountCredential = {
  [id: string]: AccountId;
  rkm: Base64UrlString;
};

// ============================================================================
// 8. ACCOUNT LAYER
// ============================================================================

type AccountAccessDependencies = {
  id: AccountId;
  rkm: AccountCredential["rkm"];
};

type CipherAccount = EncryptedEnvelope;

type AccountStorage = {
  [id: AccountId]: CipherAccount;
};

type ResourceId = `${string}:${UUIDv4}`;

type ResourceCredential = {
  id: ResourceId;
  rkm: Base64UrlString;
};

type Account = ResourceCredential[];

// ============================================================================
// 9. PSEUDORANDOM SUBJECT TOKEN
// ============================================================================

type PseudoRandomIdentityClaims = {
  sub: AccountId;
  aud: string;
  iat: number;
  exp?: number;
};

type PseudoRandomIdentity = Base64UrlString;

// ============================================================================
// 10. RESOURCE + ACL MODEL
// ============================================================================

type Action =
  | "resource:read"
  | "resource:write"
  | "resource:delete"
  | "resource:share"
  | "acl:manage";

type Effect = "allow" | "deny";

type Condition = {
  timeBefore?: number;
  timeAfter?: number;
};

type ResourceAclEntry = {
  subject: AccountId;
  effect: Effect;
  actions: Action[];
  conditions?: Condition[];
};

type ResourceKeyDerivations = {
  symmetricKey: CryptoKey;
  signingKeyPair: {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
  };
};

type ResourceAccessDependencies = {
  id: ResourceId;
  token: PseudoRandomIdentity;
  rkm: Base64UrlString;
};

type Resource = {
  acl: ResourceAclEntry[];
  payload: EncryptedEnvelope;
};

type ResourceStorage = { [id: ResourceId]: Resource }[];

// ============================================================================
// 11. FLOW CONTRACTS
// ============================================================================

type FlowContract = {
  name:
    | "VerifyIdentity"
    | "UnlockCredential"
    | "UnlockAccount"
    | "AccessResource";
  requires: readonly string[];
  provides: readonly string[];
  forbidden: readonly string[];
};

const flows: readonly FlowContract[] = [
  {
    name: "VerifyIdentity",
    requires: [
      "Valid WebAuthn assertion",
      "User verification == true",
      "signCount monotonic per credential",
    ],
    provides: ["AuthenticationResult == true"],
    forbidden: ["Server derives decryption keys"],
  },
  {
    name: "UnlockCredential",
    requires: ["AuthenticationResult == true", "Client has PRF-derived rkm"],
    provides: ["AccountCredential plaintext in client runtime"],
    forbidden: ["Server sees credential plaintext"],
  },
  {
    name: "UnlockAccount",
    requires: ["Client has account rkm"],
    provides: ["Account plaintext in client runtime"],
    forbidden: ["Server sees account plaintext"],
  },
  {
    name: "AccessResource",
    requires: [
      "ACL allows action for token.sub",
      "Request signed with key derived from rkm",
    ],
    provides: ["Encrypted read/write"],
    forbidden: ["Server decrypts resource payload"],
  },
] as const;

// ============================================================================
// 12. INVARIANTS
// ============================================================================

type InvariantLevel = "MUST" | "MUST_NOT";

type Invariant = {
  id: `${string}:${number}`;
  level: InvariantLevel;
  statement: string;
  violatedIf: readonly string[];
};

const invariants: readonly Invariant[] = [
  {
    id: "ZK:1",
    level: "MUST_NOT",
    statement:
      "The server must never learn any decryption key or plaintext payload.",
    violatedIf: ["Server derives or stores a decryption key"],
  },
  {
    id: "SUB:1",
    level: "MUST",
    statement:
      "ACL subjects must be pseudorandom AccountId values, not human or device identifiers.",
    violatedIf: ["ACL subject equals credentialId or email"],
  },
  {
    id: "AUTHZ:1",
    level: "MUST",
    statement:
      "Authorization requires both ACL permission and proof of key possession.",
    violatedIf: ["ACL match without signature or signature without ACL"],
  },
];

// ============================================================================
// 13. VALIDATION OBLIGATIONS
// ============================================================================

type ValidationObligation = {
  by: "server" | "client";
  mustCheck: readonly string[];
};

const validation: readonly ValidationObligation[] = [
  {
    by: "server",
    mustCheck: [
      "WebAuthn assertion validity",
      "Token validity",
      "ACL evaluation",
      "Request signature verification",
    ],
  },
  {
    by: "client",
    mustCheck: [
      "Never persist derived private keys",
      "Never transmit decryption keys",
    ],
  },
];

// ============================================================================
// 14. FAILURE MODES
// ============================================================================

type FailureMode = {
  trigger: string;
  result: string;
};

const failureModes: readonly FailureMode[] = [
  {
    trigger: "Authentication failure",
    result: "No access to any credentials or resources",
  },
  {
    trigger: "Missing rkm path",
    result: "Data remains encrypted and inaccessible",
  },
];

// ============================================================================
// 15. CAPABILITY PREDICATES
// ============================================================================

declare function canReadResource(
  resource: Resource,
  deps: ResourceAccessDependencies
): boolean;

declare function canWriteResource(
  resource: Resource,
  deps: ResourceAccessDependencies
): boolean;

declare function canDeleteResource(
  resource: Resource,
  deps: ResourceAccessDependencies
): boolean;

declare function canShareResource(
  resource: Resource,
  deps: ResourceAccessDependencies
): boolean;

declare function canManageAcl(
  resource: Resource,
  deps: ResourceAccessDependencies
): boolean;
