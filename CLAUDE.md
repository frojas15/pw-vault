# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm install       # install dependencies
npm run dev       # start Vite dev server (localhost:5173)
npm run build     # tsc -b && vite build → outputs to dist/
npm run lint      # ESLint (TypeScript + react-hooks + react-refresh rules)
npm run preview   # serve the production build locally
```

There is no test suite configured in this project.

## Architecture

The entire frontend is a single React component in `src/App.tsx`. There are no sub-components, no routing library, and no state-management library—all state is `useState`/`useCallback`/`useMemo` hooks inside the one `App` function.

### Encryption model

All crypto runs in the browser via the Web Crypto API:

- **Vault storage**: master password → PBKDF2 (250 000 iterations, SHA-256) → AES-GCM-256 key → encrypts `VaultPayload` JSON → stored as a JSON blob in `localStorage` under key `password_vault_blob_v1`.
- **Biometric unlock**: WebAuthn PRF extension produces a secret → HKDF → AES-GCM-256 wrapping key → wraps (encrypts) the master password itself → stored in `localStorage` under `password_vault_webauthn`.
- The password generator uses rejection sampling (`randomIndex`) to eliminate modulo bias and ensures every character class is represented.

### Data types

```ts
VaultItem    = { id, title, username, password, website, notes, tags: string[], updatedAt }
VaultPayload = { items: VaultItem[] }
EncryptedBlob = { salt?, iv, data, version }          // base64-encoded fields
WebAuthnVaultCredential = { credentialId, prfSalt, wrappedMasterPassword, timestamp, version }
SyncConfig   = { workerUrl, token, username }          // stored in localStorage
ModalMode    = 'view' | 'add' | 'edit' | null
```

### UI state machine

`modalMode` drives all modal rendering. `null` = no modal. The entry form (`entryForm` JSX variable) is shared between `'add'` and `'edit'` modes; `editingId` distinguishes them. Escape and backdrop click both call `closeModal()`.

### Cloud sync

Optional sync to a self-hosted Cloudflare Worker (`worker/index.js`). The encrypted blob is pushed/pulled as-is—the server never sees plaintext. Merge strategy on unlock: iterate server items and replace local items where `server.updatedAt > local.updatedAt` (last-write-wins per `id`). After any merge that produces changes, the merged blob is re-encrypted and pushed back.

Sync state lives in `localStorage` under `password_vault_sync_v1` as a `SyncConfig`. `syncConfigRef` is a ref kept in sync with `syncConfig` state so async callbacks can read the latest config without stale closures.

### Cloudflare Worker (`worker/`)

`worker/index.js` is deployed manually to Cloudflare Workers (paste into the dashboard or use Wrangler). It requires a D1 database binding named `DB`. Run `worker/schema.sql` against the D1 database before first use. Sessions expire in 90 days. The worker is not part of the Vite/Node build pipeline.

### PWA / build

Vite is configured with:
- `@vitejs/plugin-react` for Fast Refresh
- `@rolldown/plugin-babel` + `babel-plugin-react-compiler` (React Compiler) — the compiler auto-memoizes; avoid unnecessary manual `useMemo`/`useCallback` for simple cases, but keep the existing ones that guard against referential identity issues in effects.
- `vite-plugin-pwa` — generates a service worker with `autoUpdate`, caches all JS/CSS/HTML/SVG assets. The PWA manifest is defined inline in `vite.config.ts`.

### Deployment

Pushing to `main`/`master` triggers `.github/workflows/deploy.yml`, which runs `npm ci && npm run build` and deploys `dist/` to GitHub Pages.
