# Password Vault

A mobile-friendly password manager web app with local encrypted storage.

## Features

- Master password setup and unlock
- AES-GCM encrypted vault in browser localStorage
- Add, edit, delete entries
- Strong password generator
- Copy username/password buttons
- Search entries
- Auto-lock timer

## Run

```bash
npm install
npm run dev
```

Build for production:

```bash
npm run build
```

## Security Notes

- The vault data is encrypted using the Web Crypto API and a key derived from your master password (PBKDF2 + AES-GCM).
- Data is stored only in this browser on this device.
- If you lose your master password, the data cannot be recovered.
- For clipboard copy to work reliably, run in a secure context (localhost or HTTPS).
