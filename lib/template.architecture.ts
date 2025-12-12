// lib/_template.architecture.ts
// ARCHITECTURE SPECIFICATION TEMPLATE (types-as-truth)
// This file is a *format contract* for all `*.architecture.ts` specs.
//
// RULES:
// - No runtime code. Types + declare-only signatures are allowed.
// - Every section below MUST exist in every architecture file.
// - "MUST / MUST NOT / SHOULD / MAY" are normative keywords.
// - Anything not explicitly allowed is implicitly forbidden.

// ============================================================================
// 0. METADATA (MANDATORY)
// ============================================================================

type SpecMetadata = {
  specName: string; // e.g. "zk-iam"
  specVersion: string; // e.g. "1.2.0"
  lastEdited: `${number}-${number}-${number}`; // YYYY-M-D, not validated
  status: "draft" | "stable" | "deprecated";
  authorship: "human-led" | "ai-assisted" | "ai-generated"; // provenance only
};

// ============================================================================
// 1. PURPOSE, SCOPE, NON-GOALS (MANDATORY)
// ============================================================================

type SpecPurpose = {
  purpose: string; // single paragraph
  scope: string[]; // bullets; each is a testable statement
  nonGoals: string[]; // bullets; explicitly out-of-scope
};

// ============================================================================
// 2. TRUST MODEL (MANDATORY)
// ============================================================================
// Define what is trusted, where plaintext may exist, and what boundaries exist.

type TrustZone =
  | "client-runtime" // JS memory, secure enclave interactions, etc.
  | "client-storage" // IDB / FS / disk; assume compromise unless stated
  | "network" // hostile by default
  | "server-runtime" // code execution on server; hostile by default
  | "server-storage" // DB/object store; hostile by default
  | "third-party"; // email/SMS/OIDC/etc.

type TrustModel = {
  // Plaintext rules MUST be explicit.
  plaintextAllowedIn: TrustZone[]; // zones where plaintext is allowed
  plaintextForbiddenIn: TrustZone[]; // zones where plaintext MUST NOT exist
  keyMaterialForbiddenIn: TrustZone[]; // zones where raw keys MUST NOT exist

  // What identities can the server correlate?
  serverObservability: {
    canCorrelateStableAccount?: boolean;
    canCorrelatePerCredential?: boolean;
    canCorrelatePerResource?: boolean;
    notes: string[];
  };
};

// ============================================================================
// 3. THREAT MODEL (MANDATORY)
// ============================================================================
// Explicit attacker capabilities. Keep it brutal and concrete.

type AttackerCapability =
  | "read-server-storage"
  | "write-server-storage"
  | "read-client-storage"
  | "write-client-storage"
  | "observe-network"
  | "replay-network"
  | "reorder-network"
  | "drop-network"
  | "malicious-client"
  | "malicious-server"
  | "compromised-third-party"
  | "stolen-device"
  | "cloned-authenticator"
  | "phishing-origin"
  | "xss-in-origin";

type ThreatModel = {
  assumedCapabilities: AttackerCapability[];
  explicitlyOutOfScope: AttackerCapability[];
  securityGoals: string[]; // e.g. "server cannot decrypt payloads"
};

// ============================================================================
// 4. CRYPTO / ENVELOPE CONVENTIONS (MANDATORY)
// ============================================================================
// This section defines the generic ciphertext shapes.

type Base64UrlString = string;
type UUIDv4 = string;

type EncryptedEnvelope = {
  alg: string; // e.g. "AES-256-GCM"
  iv: ArrayBuffer;
  salt?: ArrayBuffer;
  tag?: ArrayBuffer;
  ciphertext: ArrayBuffer; // encrypted document bytes
};

type SignatureEnvelope = {
  alg: string; // e.g. "Ed25519" / "ES256"
  publicKey: Base64UrlString; // the server-verifiable public key representation
  signature: Base64UrlString; // signature over canonical request bytes
};

// ============================================================================
// 5. DOMAIN ENTITIES & IDS (MANDATORY)
// ============================================================================
// All IDs used in this spec MUST be declared here.

type EntityId = string;

type EntityIndex = {
  // Example:
  // accountId: `account:${UUIDv4}`;
  // resourceId: `${string}:${UUIDv4}`;
  [entityName: string]: EntityId;
};

// ============================================================================
// 6. DATA SHAPES (MANDATORY)
// ============================================================================
// Every stored thing MUST be either (a) envelope-wrapped or (b) explicitly
// declared as safe plaintext with rationale.

type StorageClass = "server-storage" | "client-storage" | "both";

type StoredRecord = {
  id: EntityId;
  storage: StorageClass;
  envelope?: EncryptedEnvelope; // if confidential
  plaintext?: unknown; // if safe; MUST be justified in invariants
  publicMetadata?: Record<string, unknown>; // explicitly non-confidential fields
};

type StorageSchema = {
  // Example:
  // VerifierStorage: { [id: VerifierId]: StoredRecord }
  [storageName: string]: unknown;
};

// ============================================================================
// 7. DEPENDENCY GRAPH (MANDATORY)
// ============================================================================
// Every access path MUST be expressed as a dependency object that states:
// - what must be true beforehand,
// - what is fetched,
// - what key material is required (as opaque handles),
// - what is derived only in client runtime.

type Dependency = {
  name: string;
  prerequisites: string[]; // e.g. ["auth.greenlight == true"]
  inputs: Record<string, unknown>;
  fetches: Record<string, EntityId | unknown>;
  derivesClientSide: Record<string, unknown>; // keys, claims, etc.
  outputs: Record<string, unknown>;
};

type DependencyGraph = {
  steps: Dependency[];
};

// ============================================================================
// 8. INVARIANTS (MANDATORY)
// ============================================================================
// This is the core “grammar”: invariants are structured and audit-friendly.

type InvariantLevel = "MUST" | "MUST_NOT" | "SHOULD" | "MAY";

type Invariant = {
  id: `${string}:${number}`; // e.g. "ZK:1"
  level: InvariantLevel;
  statement: string; // single testable sentence
  rationale: string; // why this exists
  violatesIf: string[]; // concrete failure conditions
};

type Invariants = {
  invariants: Invariant[];
};

// ============================================================================
// 9. KEY LIFECYCLE (MANDATORY)
// ============================================================================
// Generation, wrapping, rotation, revocation, deletion semantics.

type KeyMaterialKind =
  | "session-rkm"
  | "credential-rkm"
  | "account-rkm"
  | "resource-rkm"
  | "symmetric-key"
  | "signing-private"
  | "signing-public";

type KeyLifecycleRule = {
  kind: KeyMaterialKind;
  generatedIn: TrustZone; // where it is created
  persistedIn: TrustZone[]; // where it may be stored (usually none)
  wrappedAs?: EncryptedEnvelope; // how it is stored if persisted
  rotationTriggers: string[]; // e.g. "new credential added"
  revocationMechanism: string[]; // e.g. "remove ACL + rotate resource key"
  lossConsequence: string; // MUST be explicit and conditional
};

type KeyLifecycle = {
  rules: KeyLifecycleRule[];
};

// ============================================================================
// 10. AUTHORIZATION MODEL (MANDATORY)
// ============================================================================

type Action = string;
type Effect = "allow" | "deny";

type Condition = {
  timeBefore?: number;
  timeAfter?: number;
};

type AclEntry = {
  subject: EntityId; // MUST reference a declared subject type/ID scheme
  effect: Effect;
  actions: Action[];
  conditions?: Condition[];
};

type AuthorizationSemantics = {
  denyPrecedence: "deny-wins" | "allow-wins" | "ordered";
  orderedRuleField?: "priority" | "index";
  conditionTimeSource: "server-time" | "client-time" | "hybrid";
  canonicalization: string[]; // what bytes are signed / compared
};

// ============================================================================
// 11. VALIDATION OBLIGATIONS (MANDATORY)
// ============================================================================
// What must be validated, by whom, and what happens on failure.

type ValidationObligation = {
  id: `${string}:${number}`; // e.g. "VAL:3"
  verifier: "client" | "server" | "both";
  checks: string[]; // concrete checks
  onFailure: "deny" | "hard-fail" | "retry" | "lockout";
  notes?: string[];
};

type Validation = {
  obligations: ValidationObligation[];
};

// ============================================================================
// 12. FAILURE MODES (MANDATORY)
// ============================================================================

type FailureMode = {
  id: `${string}:${number}`; // e.g. "FAIL:2"
  trigger: string; // concrete trigger condition
  impact: string; // what breaks
  expectedBehavior: string; // what system MUST do
  recoverability: "none" | "manual" | "automatic" | "conditional";
};

type Failures = {
  modes: FailureMode[];
};

// ============================================================================
// 13. CONCEPTUAL PREDICATES (OPTIONAL BUT RECOMMENDED)
// ============================================================================
// declare-only capability checks. Never implement here.

declare function canDo(
  action: Action,
  subject: EntityId,
  target: EntityId,
  acl: AclEntry[],
  context: { nowMs: number }
): boolean;

// ============================================================================
// 14. SPEC INSTANCE (MANDATORY)
// ============================================================================
// Every architecture file MUST end by instantiating these top-level spec objects.
// This forces completeness and makes omissions obvious in diffs.

type ArchitectureSpec = {
  meta: SpecMetadata;
  purpose: SpecPurpose;
  trust: TrustModel;
  threat: ThreatModel;
  entityIndex: EntityIndex;
  storage: StorageSchema;
  dependencies: DependencyGraph;
  invariants: Invariants;
  keyLifecycle: KeyLifecycle;
  authz: AuthorizationSemantics;
  validation: Validation;
  failures: Failures;
};
