# Architecture Types

Personal design platform for drafting system architectures as TypeScript declaration files. These sketches are the source of truth for ideas I want to turn into future libraries and products, and they are shared here as a reference for anyone curious.

## What lives here

- Architecture drafts expressed as lightweight type definitions—no runtime code.
- Each concept lives in its own `*.architecture.ts` file under `lib/`, keeping experiments isolated and easy to diff.
- Files focus on shapes, invariants, and data flow boundaries (e.g., storage-level ciphertext vs. runtime-only keys).

## How to read and use the drafts

- Follow inline comments in the declaration files; they capture intent, constraints, and the trust model.
- Copy types into prototypes or tests when exploring storage, rotation, or recovery flows.
- Add new architectures by dropping another declaration file into `lib/`; the repo stays build-free and portable.

## Repo structure

- `README.md` — overview (you’re here).
- `lib/` — collection of `*.architecture.ts` sketches.

## Intent and scope

- Built first for my own design thinking; shared as a potential reference for others.
- Truth lives in the declarations: they describe desired shapes and invariants, not a production implementation.
