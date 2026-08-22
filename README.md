# BioLock — Smartphone Biometric PC Authorization System

**Your Phone. Your Fingerprint. Your PC.**

BioLock is a hackathon prototype where a trusted smartphone authorizes access to a PC demo environment. The phone/platform handles biometric verification; BioLock never receives or stores fingerprint data.

## Architecture

PC React/Vite client <-> Node/Express/Socket.IO server <-> Mobile React/Vite client

SQLite stores device, request, authentication and security-event metadata only.

## Important prototype limitation

This project does **not** unlock Windows itself. "Unlocked" means the BioLock protected demo environment is unlocked. A production version could integrate with Windows Credential Provider, Windows Hello, TPM/FIDO2 and enterprise identity systems.

The project now includes a **real WebAuthn/passkey path**. The phone browser invokes the platform authenticator, and the server verifies the signed WebAuthn assertion using the registered public key. The server never receives raw biometric data.

There is still a separate demo/fallback concept for presentations, but the recommended competition flow is the real WebAuthn path.

## Run

### Server
```bash
cd server
npm install
copy .env.example .env
npm run dev
```

Linux/macOS:
```bash
cp .env.example .env
npm run dev
```

### PC
```bash
cd pc-client
npm install
npm run dev -- --host 0.0.0.0
```

### Mobile
```bash
cd mobile-client
npm install
npm run dev -- --host 0.0.0.0
```

Open the PC client at `http://localhost:5173`. The mobile client is normally `http://localhost:5174`.

For LAN testing, find the PC IPv4 address with `ipconfig`, then open the Vite mobile URL from the phone while both devices are on the same Wi-Fi. Set `VITE_API_URL` to the PC's LAN server address if needed.

## Demo

1. Open PC client.
2. Generate an authorization QR.
3. Open the mobile client and use the QR/request flow.
4. Choose **DEMO AUTHENTICATION**.
5. Approve.
6. Watch the PC transition to BIOLOCK UNLOCKED.
7. Try DENY.
8. Try the expired-request or unauthorized-attempt demos.
9. Show Security Dashboard.

## Security model

- No raw biometric data is collected or stored.
- QR contains a short-lived random request ID and expiration.
- Requests are one-time use.
- Server validates request status and expiry.
- Rate limiting is enabled.
- Helmet and CORS are enabled.
- Secrets are configured through `.env`.
- Recovery is rate-limited and creates security events.

## Future production roadmap

- Real WebAuthn/passkeys with server-side assertion verification
- Windows Credential Provider
- Windows Hello / TPM / FIDO2
- Enterprise identity providers
- Multiple PCs and phones
- Device management and audit reports
- Risk-based authentication
- Optional cloud synchronization

## 2-minute pitch

BioLock turns an existing smartphone into a trusted authorization device for PC access. Instead of installing a fingerprint sensor on every computer, the user's phone performs platform-level authentication and the PC receives an authorization result. The key privacy principle is simple: biometric information stays on the phone.

## Judge answers

**Why not a password?** Passwords can be reused, shared or phished. BioLock moves verification to a trusted device.

**Is fingerprint data stored?** No.

**Does the server receive a fingerprint?** No. A production WebAuthn implementation would receive cryptographic authentication data.

**Can the QR be replayed?** Requests expire quickly and are marked used after completion.

**What if the phone is lost?** Revoke the trusted device and use the emergency recovery path.

**Is this production-ready?** No. This is a competition prototype. Production requires OS integration, stronger device lifecycle management, WebAuthn verification and security review.


## REAL BIOMETRIC / PASSKEY DEMO

WebAuthn is a secure-context browser API. For a phone accessing a PC over the network, use an HTTPS hostname/tunnel. `localhost` is treated as trustworthy for local browser testing, but a phone's LAN IP over plain HTTP is not a suitable WebAuthn origin.

### 1. Install dependencies
```bash
cd server
npm install
cd ../pc-client
npm install
cd ../mobile-client
npm install
```

### 2. Build both clients
```bash
cd ../pc-client
npm run build
cd ../mobile-client
npm run build
```

The server serves the built PC at `/pc/` and phone app at `/mobile/`.

### 3. Use one HTTPS origin
Set `.env`:
```env
RP_NAME=BioLock
RP_ID=YOUR_HTTPS_HOSTNAME
ORIGIN=https://YOUR_HTTPS_HOSTNAME
PUBLIC_BASE_URL=https://YOUR_HTTPS_HOSTNAME
MOBILE_PATH=/mobile/
```

Then expose the server's port 5000 through a trusted HTTPS tunnel or deploy it behind HTTPS.

### 4. Open the phone app
Open:
`https://YOUR_HTTPS_HOSTNAME/mobile/`

Tap **REGISTER THIS PHONE**. The phone's platform authenticator will appear. Complete the phone's biometric/passkey verification.

### 5. Authorize the PC
Open:
`https://YOUR_HTTPS_HOSTNAME/pc/`

Generate a QR. Scan it with the phone. The phone opens the authorization request. Tap **AUTHENTICATE WITH PHONE** and complete the phone authenticator prompt.

The server then verifies the WebAuthn signature and emits `pc:access-granted`.

### Why HTTPS matters
WebAuthn is restricted to secure contexts. Public network origins should use HTTPS. `localhost` is a special trusted development origin.
