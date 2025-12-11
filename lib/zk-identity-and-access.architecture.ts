// 1) Storage-level (cloud / offline) – ONLY encrypted envelopes

type EncryptedEnvelope = {
  alg: string;
  iv: ArrayBuffer;
  salt?: ArrayBuffer;
  tag?: ArrayBuffer;
  ciphertext: ArrayBuffer; // serialized JSON payload
};

type WebauthnResult = {
  credentialId: string; // lookup-key
  credentialEk: CryptoKey; // PRF result, session-bound, never persisted
};

type ServiceCredentialStorage = {
  [credentialId: string]: EncryptedEnvelope;
  // ciphertext = JSON.stringify({ accountId, accountMk })
};

type AccountStorage = {
  [accountId: string]: EncryptedEnvelope;
  // ciphertext = JSON.stringify({
  //   id: accountId,
  //   resources: [
  //     { url: string, ek: string }, // ek = random resource key (wrapped when stored)
  //   ]
  // })
};

// 2) Runtime-level (in-memory) – decrypted view

type ServiceCredential = {
  accountId: string; // pseudo-random
  accountMk: CryptoKey; // random master key
};

type Account = {
  id: string; // accountId
  ek: CryptoKey; // == accountMk, used to unwrap resource keys
  resources: [
    {
      url: string; // namespace:uuid
      ek: CryptoKey; // raw symmetric key for this resource, only in memory
    }
  ];
};
