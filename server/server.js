require("dotenv").config();
const express = require("express");
const https = require("https");
const path = require("path");
const fs = require("fs");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Server } = require("socket.io");
const QRCode = require("qrcode");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
// const {
//   generateRegistrationOptions,
//   verifyRegistrationResponse,
//   generateAuthenticationOptions,
//   verifyAuthenticationResponse
// } = require("@simplewebauthn/server");

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

const db = require("./database");

const app = express();
const server = https.createServer(
  {
   key: fs.readFileSync(
  path.join(__dirname, "../certs/biolock.local+2-key.pem")
),
cert: fs.readFileSync(
  path.join(__dirname, "../certs/biolock.local+2.pem")
),
  },
  app
);
const PORT = Number(process.env.PORT || 5000);
const RP_NAME = process.env.RP_NAME || "BioLock";
const RP_ID = process.env.RP_ID || "localhost";
const ORIGIN = process.env.ORIGIN || "https://soma-beam-fragrance-wanting.trycloudflare.com";
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || ORIGIN;
const MOBILE_PATH = process.env.MOBILE_PATH || "/mobile/";
const AUTH_SESSION_MS = Number(process.env.AUTH_SESSION_MINUTES || 30) * 60 * 1000;
  
console.log("ENV PUBLIC_BASE_URL =", process.env.PUBLIC_BASE_URL);
console.log("ENV MOBILE_PATH =", process.env.MOBILE_PATH);

app.set("trust proxy", 1);
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "100kb" }));
app.use(rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true }));

const io = new Server(server, {
  cors: { origin: true, methods: ["GET", "POST", "DELETE"] }
});

const pcAgentSockets = new Map();

const nowIso = () => new Date().toISOString();

function addSecurityEvent(type, severity, deviceId, message) {

  const createdAt = nowIso();

  const result = db.prepare(`
    INSERT INTO security_events
    (event_type, severity, device_id, message, created_at)
    VALUES (?,?,?,?,?)
  `).run(
    type,
    severity,
    deviceId || null,
    message,
    createdAt
  );

  const event = {
    id: Number(result.lastInsertRowid),
    event_type: type,
    severity,
    device_id: deviceId || null,
    message,
    created_at: createdAt
  };

  // 🔴 REAL-TIME SECURITY EVENT
if (typeof io !== "undefined") {
  io.emit("security:event-created", event);
}

  console.log("📡 LIVE SECURITY EVENT:", event);
}

const finalizeAuthentication = db.transaction(({
  challengeId,
  passkeyId,
  newCounter,
  requestId,
  deviceId,
  targetPcId,
  authorizationTime,
}) => {

  // 1. FINAL TRUST CHECK — transaction ke andar
  const trust = db.prepare(`
    SELECT status
    FROM trusted_devices
    WHERE device_id=?
    LIMIT 1
  `).get(deviceId);

  if (!trust || trust.status !== "trusted") {
    throw new Error("DEVICE_TRUST_REVOKED");
  }

  // 2. Consume challenge atomically
  const challengeUpdate = db.prepare(`
    UPDATE webauthn_challenges
    SET used=1
    WHERE id=? AND used=0
  `).run(challengeId);

  if (challengeUpdate.changes !== 1) {
    throw new Error("AUTH_CHALLENGE_ALREADY_USED");
  }

  // 3. Approve authentication request atomically
  const requestUpdate = db.prepare(`
    UPDATE auth_requests
    SET phone_device_id=?,
        status='approved',
        used_at=?
    WHERE request_id=?
      AND status='pending'
  `).run(
    deviceId,
    authorizationTime,
    requestId
  );

  if (requestUpdate.changes !== 1) {
    throw new Error("AUTH_REQUEST_ALREADY_USED");
  }

  // 4. Update WebAuthn counter
  const counterUpdate = db.prepare(`
    UPDATE passkeys
    SET counter=?
    WHERE id=?
  `).run(
    newCounter,
    passkeyId
  );

  if (counterUpdate.changes !== 1) {
    throw new Error("PASSKEY_UPDATE_FAILED");
  }

  // 5. Authorize target PC
  const pcUpdate = db.prepare(`
    UPDATE pc_devices
    SET authorized=1,
        authorized_device=?,
        authorized_at=?,
        status='online',
        last_seen=?,
        updated_at=?
    WHERE pc_device_id=?
  `).run(
    deviceId,
    authorizationTime,
    authorizationTime,
    authorizationTime,
    targetPcId
  );

  if (pcUpdate.changes !== 1) {
    throw new Error("PC_DEVICE_NOT_FOUND");
  }

  return true;
});

const ensureDevice = (deviceId, type, name) => {
  const existing = db.prepare("SELECT * FROM devices WHERE device_id=?").get(deviceId);
  if (!existing) {
    db.prepare(`INSERT INTO devices(device_id,device_type,device_name,status,created_at,last_seen)
      VALUES(?,?,?,?,?,?)`).run(deviceId,type,name,"active",nowIso(),nowIso());
  } else {
    db.prepare("UPDATE devices SET last_seen=? WHERE device_id=?").run(nowIso(),deviceId);
  }
};



const pcDist = path.join(__dirname,"..","pc-client","dist");
const mobileDist = path.join(__dirname,"..","mobile-client","dist");
if (fs.existsSync(pcDist)) {
  app.use("/pc", express.static(pcDist));
  app.get("/pc/*splat", (req,res)=>res.sendFile(path.join(pcDist,"index.html")));
}
if (fs.existsSync(mobileDist)) {
  app.use(
    "/mobile",
    express.static(mobileDist)
  );

  app.get("/mobile", (req, res) => {
    res.sendFile(
      path.join(mobileDist, "index.html")
    );
  });

  app.get("/mobile/*splat", (req, res) => {
    res.sendFile(
      path.join(mobileDist, "index.html")
    );
  });
}

app.get("/api/health", (_, res) => res.json({ name:"BioLock Server", status:"online", time:nowIso() }));


function getPasskeys(deviceId){
  return db.prepare("SELECT * FROM passkeys WHERE device_id=?").all(deviceId);
}
function saveChallenge(kind, challenge, requestId=null){
  db.prepare(`INSERT INTO webauthn_challenges(kind,challenge,request_id,created_at,expires_at)
    VALUES(?,?,?,?,?)`).run(kind,challenge,requestId,nowIso(),Date.now()+120000);
}
function consumeChallenge(kind, challenge){
  const row=db.prepare(`SELECT * FROM webauthn_challenges
    WHERE kind=? AND challenge=? AND used=0 ORDER BY id DESC LIMIT 1`).get(kind,challenge);
  if(!row || Date.now()>row.expires_at) return false;
  db.prepare("UPDATE webauthn_challenges SET used=1 WHERE id=?").run(row.id);
  return row;
}

app.get("/api/webauthn/status", (req, res) => {
  try {
    const deviceId = String(
      req.query.deviceId ||
      "GHANARAM-PHONE"
    );

    const count = db
      .prepare(`
        SELECT COUNT(*) AS c
        FROM passkeys
        WHERE device_id=?
      `)
      .get(deviceId).c;

    res.json({
      registered: Number(count) > 0,
      rpId: RP_ID,
      origin: ORIGIN,
      secureContextRequired:
        ORIGIN.startsWith("https://"),
    });

  } catch (e) {
    res.status(500).json({
      registered: false,
      error: e.message,
    });
  }
});

app.get("/api/webauthn/register/options", async (req,res)=>{
  try{
    const deviceId=String(req.query.deviceId||"GHANARAM-PHONE");
    const existing=getPasskeys(deviceId);
    const options=await generateRegistrationOptions({
      rpName:RP_NAME,
      rpID:RP_ID,
      userName:"Ghanaram",
      userDisplayName:"Ghanaram's Phone",
      attestationType:"none",
      userID:Buffer.from(`biolock:${deviceId}`),
      excludeCredentials:existing.map(p=>({id:p.id,transports:p.transports?JSON.parse(p.transports):undefined})),
      authenticatorSelection:{
        residentKey:"required",
        userVerification:"required",
        authenticatorAttachment:"platform"
      },
      supportedAlgorithmIDs:[-7,-257]
    });
    saveChallenge("registration",options.challenge,deviceId);
    res.json(options);
  }catch(e){res.status(500).json({error:e.message})}
});

app.post("/api/webauthn/register/verify", async (req,res)=>{
  try{
    const deviceId=String(req.body.deviceId||"GHANARAM-PHONE");
    const response=req.body.response;
    
    // --------------------------------------------------
// Registration challenge must belong to this device
// --------------------------------------------------

const row = db.prepare(`
  SELECT *
  FROM webauthn_challenges
  WHERE kind='registration'
    AND request_id=?
    AND used=0
  ORDER BY id DESC
  LIMIT 1
`).get(deviceId);

if (!row) {
  addSecurityEvent(
    "UNAUTHORIZED",
    "WARNING",
    deviceId,
    "Registration attempted without a valid device-bound challenge."
  );

  return res.status(400).json({
    verified: false,
    error: "No active registration challenge for this device"
  });
}

if (Date.now() > row.expires_at) {

  db.prepare(`
    UPDATE webauthn_challenges
    SET used=1
    WHERE id=? AND used=0
  `).run(row.id);

  addSecurityEvent(
    "EXPIRED",
    "WARNING",
    deviceId,
    "Registration challenge expired."
  );

  return res.status(410).json({
    verified: false,
    error: "Registration challenge expired"
  });
}

    const verification=await verifyRegistrationResponse({
      response,
      expectedChallenge:row.challenge,
      expectedOrigin:ORIGIN,
      expectedRPID:RP_ID,
      requireUserVerification:true
    });
    if(!verification.verified) return res.status(400).json({error:"Passkey registration was not verified"});
    
    const challengeUpdate = db.prepare(`
  UPDATE webauthn_challenges
  SET used=1
  WHERE id=? AND used=0
`).run(row.id);

if (challengeUpdate.changes !== 1) {
  addSecurityEvent(
    "REPLAY",
    "WARNING",
    deviceId,
    "Registration challenge was already consumed."
  );

  return res.status(409).json({
    verified: false,
    error: "Registration challenge already used"
  });
}

    const {credential}=verification.registrationInfo;
    db.prepare(`INSERT OR REPLACE INTO passkeys
      (id,device_id,public_key,counter,transports,created_at) VALUES(?,?,?,?,?,?)`)
      .run(credential.id,deviceId,Buffer.from(credential.publicKey),credential.counter,
        JSON.stringify(credential.transports||[]),nowIso());
    ensureDevice(deviceId,"phone","Ghanaram's Phone");
    db.prepare(`INSERT OR REPLACE INTO trusted_devices
      (device_id,owner_name,authentication_method,status,paired_at)
      VALUES(?,?,?,?,?)`).run(deviceId,"Ghanaram","WebAuthn Passkey","trusted",nowIso());
    addSecurityEvent("PAIRING","INFO",deviceId,"Phone registered with a real WebAuthn passkey.");
    res.json({verified:true,message:"Real WebAuthn passkey registered"});
  }catch(e){
    console.error(e);
    res.status(400).json({verified:false,error:e.message});
  }
});
app.post("/api/webauthn/auth/options", async (req, res) => {
  try {
    const requestId = String(req.body.requestId || "");
    const deviceId = String(
      req.body.deviceId || "GHANARAM-PHONE"
    );

    if (!requestId) {
      return res.status(400).json({
        success: false,
        error: "Missing requestId",
      });
    }

    // Find active PC unlock request
    const authRequest = db
      .prepare(`
        SELECT *
        FROM auth_requests
        WHERE request_id = ?
      `)
      .get(requestId);

    if (!authRequest) {
      return res.status(404).json({
        success: false,
        error: "Unknown authentication request",
      });
    }

    if (authRequest.status !== "pending") {
      return res.status(409).json({
        success: false,
        error: "Authentication request is no longer pending",
      });
    }

    if (Date.now() > authRequest.expires_at) {
      db.prepare(`
        UPDATE auth_requests
        SET status='expired'
        WHERE request_id=?
      `).run(requestId);

      addSecurityEvent(
        "EXPIRED",
        "WARNING",
        deviceId,
        "WebAuthn authentication request expired."
      );

      return res.status(410).json({
        success: false,
        error: "Authentication request expired",
      });
    }

    // Find trusted device
const trustedDevice = db
  .prepare(`
    SELECT *
    FROM trusted_devices
    WHERE device_id=?
    LIMIT 1
  `)
  .get(deviceId);

// Block revoked / unknown device
if (!trustedDevice || trustedDevice.status !== "trusted") {

  addSecurityEvent(
    "UNAUTHORIZED",
    "WARNING",
    deviceId,
    !trustedDevice
      ? "Authentication attempted from an unknown device."
      : `Revoked device ${deviceId} attempted authentication.`
  );

  return res.status(403).json({
    success: false,
    error: !trustedDevice
      ? "Device is not trusted"
      : "Device trust has been revoked",
  });
}

// Find trusted phone passkey
const passkey = db
  .prepare(`
    SELECT *
    FROM passkeys
    WHERE device_id=?
    LIMIT 1
  `)
  .get(deviceId);

if (!passkey) {

  addSecurityEvent(
    "UNAUTHORIZED",
    "WARNING",
    deviceId,
    "Trusted device has no registered passkey."
  );

  return res.status(404).json({
    success: false,
    error: "No passkey registered for this phone",
  });
}

    // Generate fresh WebAuthn challenge
    const options =
      await generateAuthenticationOptions({
        rpID: RP_ID,

        userVerification: "required",

        allowCredentials: [
          {
            id: passkey.id,
            transports: passkey.transports
              ? JSON.parse(passkey.transports)
              : ["internal"],
          },
        ],
      });

    // IMPORTANT:
    // Bind WebAuthn challenge to the PC request
    saveChallenge(
      "authentication",
      options.challenge,
      requestId
    );
console.log("=================================");
console.log("✅ OPTIONS READY");
console.log("Request ID:", requestId);
console.log("Device ID:", deviceId);
console.log("RP ID:", RP_ID);
console.log("Challenge:", options.challenge);
console.log(
  "Allow Credentials:",
  options.allowCredentials
);
console.log("=================================");
    console.log(
      "🔐 WebAuthn challenge created"
    );

    console.log(
      "Request:",
      requestId
    );

    console.log(
      "Phone:",
      deviceId
    );

    res.json(options);

  } catch (e) {

    console.error(
      "❌ Authentication options error:",
      e
    );

    res.status(500).json({
      success: false,
      error:
        e.message ||
        "Unable to create authentication options",
    });
  }
});

app.post("/api/webauthn/auth/verify", async (req, res) => {
  try {
    const requestId = String(
      req.body.requestId || ""
    );

    const deviceId = String(
      req.body.deviceId || "GHANARAM-PHONE"
    );

    const response = req.body.response;

    if (!requestId) {
      return res.status(400).json({
        verified: false,
        error: "Missing requestId",
      });
    }

    if (!response) {
      return res.status(400).json({
        verified: false,
        error: "Missing WebAuthn response",
      });
    }

    // --------------------------------------------------
    // 1. Find PC authentication request
    // --------------------------------------------------

    const authRequest = db
      .prepare(`
        SELECT *
        FROM auth_requests
        WHERE request_id=?
      `)
      .get(requestId);

    if (!authRequest) {
      return res.status(404).json({
        verified: false,
        error: "Unknown authentication request",
      });
    }

    // --------------------------------------------------
    // 2. Replay protection
    // --------------------------------------------------

    if (authRequest.status !== "pending") {
      addSecurityEvent(
        "REPLAY",
        "WARNING",
        deviceId,
        "Authentication request was already used."
      );

      return res.status(409).json({
        verified: false,
        error: "Authentication request already used",
      });
    }

    // --------------------------------------------------
    // 3. Expiration
    // --------------------------------------------------

    if (Date.now() > authRequest.expires_at) {

      db.prepare(`
        UPDATE auth_requests
        SET status='expired'
        WHERE request_id=?
      `).run(requestId);

      addSecurityEvent(
        "EXPIRED",
        "WARNING",
        deviceId,
        "Expired WebAuthn authentication request."
      );

      return res.status(410).json({
        verified: false,
        error: "Authentication request expired",
      });
    }

    // --------------------------------------------------
    // 4. Find WebAuthn challenge bound to this request
    // --------------------------------------------------

    const challengeRow = db
      .prepare(`
        SELECT *
        FROM webauthn_challenges
        WHERE kind='authentication'
          AND request_id=?
          AND used=0
        ORDER BY id DESC
        LIMIT 1
      `)
      .get(requestId);

    if (!challengeRow) {
      return res.status(400).json({
        verified: false,
        error: "No active WebAuthn challenge",
      });
    }

    // --------------------------------------------------
    // 5. Challenge expiration
    // --------------------------------------------------

    if (Date.now() > challengeRow.expires_at) {

      db.prepare(`
        UPDATE webauthn_challenges
        SET used=1
        WHERE id=?
      `).run(challengeRow.id);

      addSecurityEvent(
        "EXPIRED",
        "WARNING",
        deviceId,
        "WebAuthn challenge expired."
      );

      return res.status(410).json({
        verified: false,
        error: "WebAuthn challenge expired",
      });
    }

    // -----------------------------------------
// FINAL DEVICE TRUST CHECK
// -----------------------------------------

const trustedDevice = db.prepare(`
  SELECT status
  FROM trusted_devices
  WHERE device_id = ?
  LIMIT 1
`).get(deviceId);

if (!trustedDevice || trustedDevice.status !== "trusted") {

  addSecurityEvent(
    "UNAUTHORIZED",
    "WARNING",
    deviceId,
    !trustedDevice
      ? "Authentication rejected: trusted device record not found."
      : `Authentication rejected: device ${deviceId} is no longer trusted.`
  );

  return res.status(403).json({
    verified: false,
    success: false,
    error: !trustedDevice
      ? "Device is not trusted"
      : "Device trust has been revoked"
  });
}

    // --------------------------------------------------
    // 6. Find exact registered credential
    // --------------------------------------------------

    const passkey = db
      .prepare(`
        SELECT *
        FROM passkeys
        WHERE id=?
          AND device_id=?
        LIMIT 1
      `)
      .get(
        response.id,
        deviceId
      );

    if (!passkey) {

      addSecurityEvent(
        "UNAUTHORIZED",
        "WARNING",
        deviceId,
        "Unknown WebAuthn credential attempted authentication."
      );

      return res.status(401).json({
        verified: false,
        error: "Unknown trusted passkey",
      });
    }

    // --------------------------------------------------
    // 7. REAL WebAuthn verification
    // --------------------------------------------------

    console.log(
      "🔐 Verifying REAL WebAuthn authentication..."
    );

    const verification =
      await verifyAuthenticationResponse({
        response,

        expectedChallenge:
          challengeRow.challenge,

        expectedOrigin:
          ORIGIN,

        expectedRPID:
          RP_ID,

        requireUserVerification:
          true,

        credential: {
          id: passkey.id,

          publicKey:
            new Uint8Array(
              passkey.public_key
            ),

          counter:
            passkey.counter,

          transports:
            passkey.transports
              ? JSON.parse(
                  passkey.transports
                )
              : ["internal"],
        },
      });

    console.log(
      "WebAuthn verification:",
      verification.verified
    );

    if (!verification.verified) {

      db.prepare(`
        UPDATE webauthn_challenges
        SET used=1
        WHERE id=?
      `).run(challengeRow.id);

      addSecurityEvent(
        "FAILED",
        "WARNING",
        deviceId,
        "WebAuthn authentication failed."
      );

      return res.status(401).json({
        verified: false,
        error: "WebAuthn verification failed",
      });
    }

// --------------------------------------------------
// FINAL AUTHORIZATION TRUST CHECK
// --------------------------------------------------

const finalTrust = db.prepare(`
  SELECT status
  FROM trusted_devices
  WHERE device_id = ?
  LIMIT 1
`).get(deviceId);

if (!finalTrust || finalTrust.status !== "trusted") {

  // Consume the challenge so it cannot be reused
  db.prepare(`
    UPDATE webauthn_challenges
    SET used=1
    WHERE id=?
  `).run(challengeRow.id);

  addSecurityEvent(
    "UNAUTHORIZED",
    "CRITICAL",
    deviceId,
    `WebAuthn credential verified, but device ${deviceId} is no longer trusted. Authorization denied.`
  );

  console.log("");
  console.log("======================================");
  console.log("🚫 FINAL TRUST CHECK FAILED");
  console.log("======================================");
  console.log("Device :", deviceId);
  console.log("Reason :", "DEVICE_NOT_TRUSTED");
  console.log("Action :", "AUTHORIZATION DENIED");
  console.log("======================================");

  return res.status(403).json({
    verified: false,
    authorized: false,
    error: "Device trust has been revoked"
  });
}

    addSecurityEvent(
  "PASSKEY_VERIFIED",
  "INFO",
  deviceId,
  "WebAuthn passkey verified successfully."
);

// --------------------------------------------------
// 8. Finalize authentication atomically
// --------------------------------------------------

const targetPcId = String(
  authRequest.pc_device_id || ""
);

if (!targetPcId) {
  return res.status(400).json({
    verified: false,
    error: "Authentication request has no PC device ID",
  });
}

const authorizationTime = nowIso();

const sessionExpiresAt =
  Date.now() + AUTH_SESSION_MS;

const expiresAt =
  new Date(sessionExpiresAt).toISOString();

const newCounter =
  verification.authenticationInfo?.newCounter ??
  passkey.counter;

try {

  finalizeAuthentication({
    challengeId: challengeRow.id,
    passkeyId: passkey.id,
    newCounter,
    requestId,
    deviceId,
    targetPcId,
    authorizationTime,
  });

} catch (transactionError) {

  console.error(
    "❌ Authentication transaction failed:",
    transactionError.message
  );

  if (transactionError.message === "DEVICE_TRUST_REVOKED") {

    addSecurityEvent(
      "UNAUTHORIZED",
      "CRITICAL",
      deviceId,
      `WebAuthn credential verified, but device ${deviceId} is no longer trusted. Authorization denied.`
    );

    return res.status(403).json({
      verified: false,
      authorized: false,
      error: "Device trust has been revoked",
    });
  }

  if (
    transactionError.message ===
    "AUTH_CHALLENGE_ALREADY_USED"
  ) {

    addSecurityEvent(
      "REPLAY",
      "WARNING",
      deviceId,
      "Authentication challenge was already consumed."
    );

    return res.status(409).json({
      verified: false,
      error: "Authentication challenge already used",
    });
  }

  if (
    transactionError.message ===
    "AUTH_REQUEST_ALREADY_USED"
  ) {

    addSecurityEvent(
      "REPLAY",
      "WARNING",
      deviceId,
      "Authentication request was already approved."
    );

    return res.status(409).json({
      verified: false,
      error: "Authentication request already used",
    });
  }

  throw transactionError;
}

console.log("======================================");
console.log("🔓 PC AUTHORIZATION STATE UPDATED");
console.log("======================================");
console.log("PC ID   :", targetPcId);
console.log("Device  :", deviceId);
console.log("State   : AUTHORIZED");
console.log("Time    :", authorizationTime);
console.log("Expires :", expiresAt);
console.log(
  "Duration:",
  AUTH_SESSION_MS / 60000,
  "minutes"
);

console.log("======================================");

// --------------------------------------------------
// LIVE DASHBOARD STATE UPDATE
// --------------------------------------------------

io.emit("pc:status-updated", {
  pcDeviceId: targetPcId,
  authorized: true,
  authorizedDevice: deviceId,
  authorizedAt: authorizationTime,
  expiresAt: new Date(sessionExpiresAt).toISOString(),
  status: "online",
});
    // --------------------------------------------------
    // 11. Authentication event
    // --------------------------------------------------

    db.prepare(`
      INSERT INTO authentication_events
      (
        request_id,
        device_id,
        authentication_method,
        result,
        created_at
      )
      VALUES(?,?,?,?,?)
    `).run(
      requestId,
      deviceId,
      "WEBAUTHN_PASSKEY",
      "SUCCESS",
      nowIso()
    );

    addSecurityEvent(
      "SUCCESS",
      "INFO",
      deviceId,
      "Real WebAuthn authentication successful."
    );

   
    // --------------------------------------------------
    // 12. Tell PC to unlock
    // --------------------------------------------------

const targetSocketId =
  pcAgentSockets.get(targetPcId);

const accessPayload = {
  requestId,
  deviceId,
  method: "WEBAUTHN_PASSKEY",
  timestamp: authorizationTime,
  pcDeviceId: targetPcId,
  expiresAt: new Date(sessionExpiresAt).toISOString(),
};

if (targetSocketId) {

  const targetSocket =
    io.sockets.sockets.get(targetSocketId);

  if (targetSocket) {

    targetSocket.emit(
      "pc:access-granted",
      accessPayload
    );
    
addSecurityEvent(
  "ACCESS_GRANTED",
  "INFO",
  deviceId,
  `PC ${targetPcId} authorized successfully using WebAuthn passkey.`
);
    console.log("");
    console.log("======================================");
    console.log("✅ TARGETED PC ACCESS GRANTED");
    console.log("======================================");
    console.log("PC ID   :", targetPcId);
    console.log("Socket  :", targetSocketId);
    console.log("Request :", requestId);
    console.log("Phone   :", deviceId);
    console.log("Method  :", "WEBAUTHN_PASSKEY");
    console.log("======================================");

  } else {

    console.log(
      "⚠️ PC socket no longer available:",
      targetPcId
    );

    addSecurityEvent(
      "PC_OFFLINE",
      "WARNING",
      targetPcId,
      "PC Agent was not connected when authorization was completed."
    );
  }

} else {

  console.log(
    "⚠️ No registered PC Agent found:",
    targetPcId
  );

  addSecurityEvent(
    "PC_OFFLINE",
    "WARNING",
    targetPcId,
    "No active PC Agent found for authorized request."
  );
}

    console.log(
      "======================================"
    );

    console.log(
      "✅ BIOLOCK PC ACCESS GRANTED"
    );

    console.log(
      "Request:",
      requestId
    );

    console.log(
      "Phone:",
      deviceId
    );

    console.log(
      "======================================"
    );

    return res.json({
      verified: true,
      ok: true,
      message:
        "Real WebAuthn authorization verified",
      deviceId,
      authenticationMethod:
        "WEBAUTHN_PASSKEY",
    });

  } catch (e) {

    console.error(
      "❌ WebAuthn verification error:"
    );

    console.error(e);

    addSecurityEvent(
      "FAILED",
      "WARNING",
      req.body?.deviceId ||
        "unknown",
      "WebAuthn verification failed."
    );

    return res.status(400).json({
      verified: false,
      error:
        e.message ||
        "WebAuthn authentication failed",
    });
  }
});

app.post("/api/auth/request", async (req, res) => {
  const pcDeviceId = String(
    req.body.pcDeviceId || "BIOLOCK-PC-01"
  );

  const requestId = uuidv4();

  const challenge = crypto.randomBytes(32).toString("hex");

  // QR request valid for 60 seconds
  const expiresAt = Date.now() + 60_000;

  ensureDevice(
    pcDeviceId,
    "pc",
    "BIOLOCK-PC-01"
  );

  db.prepare(`
    INSERT INTO auth_requests
    (request_id, pc_device_id, challenge, status, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    requestId,
    pcDeviceId,
    challenge,
    "pending",
    expiresAt,
    nowIso()
  );
  addSecurityEvent(
  "AUTH_REQUEST_CREATED",
  "INFO",
  pcDeviceId,
  `PC ${pcDeviceId} requested smartphone authorization.`
);
  // URL stored inside QR
  const qrPayload =
    `${PUBLIC_BASE_URL}${MOBILE_PATH}?request=${encodeURIComponent(requestId)}`;

  console.log("================================");
  console.log("BIOLOCK QR GENERATED");
  console.log("QR PAYLOAD:", qrPayload);
  console.log("REQUEST ID:", requestId);
  console.log("EXPIRES:", new Date(expiresAt).toLocaleTimeString());
  console.log("================================");

  // Generate high-quality QR
  const qrDataUrl = await QRCode.toDataURL(
    qrPayload,
    {
      errorCorrectionLevel: "H",
      type: "image/png",
      margin: 4,
      width: 420,
      color: {
        dark: "#000000",
        light: "#FFFFFF"
      }
    }
  );

  // Send QR to connected PC clients
  io.emit(
    "pc:create-request",
    {
      requestId,
      expiresAt,
      qrDataUrl
    }
  );

  res.json({
    requestId,
    expiresAt,
    qrDataUrl
  });
});

app.post("/api/auth/verify", (req,res) => {
  const requestId = String(req.body.requestId || "");
  const phoneDeviceId = String(req.body.phoneDeviceId || "GHANARAM-PHONE");
  const method = String(req.body.authenticationMethod || "DEMO_AUTHENTICATION");
  const reqRow = db.prepare("SELECT * FROM auth_requests WHERE request_id=?").get(requestId);

  if (!reqRow) return res.status(404).json({error:"Unknown authentication request"});
  if (reqRow.status !== "pending") {
    addSecurityEvent("REPLAY","WARNING",phoneDeviceId,"Authentication request was already used.");
    return res.status(409).json({error:"Authentication request already used"});
  }
  if (Date.now() > reqRow.expires_at) {
    db.prepare("UPDATE auth_requests SET status='expired' WHERE request_id=?").run(requestId);
    addSecurityEvent("EXPIRED","WARNING",phoneDeviceId,"Expired authentication request.");
    return res.status(410).json({error:"Authentication request expired"});
  }

  db.prepare(`UPDATE auth_requests SET phone_device_id=?,status='approved',used_at=? WHERE request_id=?`)
    .run(phoneDeviceId,nowIso(),requestId);
  db.prepare(`INSERT INTO authentication_events
    (request_id,device_id,authentication_method,result,created_at) VALUES(?,?,?,?,?)`)
    .run(requestId,phoneDeviceId,method,"SUCCESS",nowIso());

  ensureDevice(phoneDeviceId,"phone","Ghanaram's Phone");
  db.prepare(`INSERT OR IGNORE INTO trusted_devices
    (device_id,owner_name,authentication_method,status,paired_at) VALUES(?,?,?,?,?)`)
    .run(phoneDeviceId,"Ghanaram",method,"trusted",nowIso());

  io.emit("pc:access-granted",{requestId,deviceId:phoneDeviceId,method});
  res.json({ok:true,message:"Authorization approved"});
});

app.post("/api/auth/deny", (req,res) => {
  const requestId = String(req.body.requestId || "");
  const phoneDeviceId = String(req.body.phoneDeviceId || "GHANARAM-PHONE");
  const row = db.prepare("SELECT * FROM auth_requests WHERE request_id=?").get(requestId);
  if (!row) return res.status(404).json({error:"Unknown authentication request"});
  if (row.status !== "pending") return res.status(409).json({error:"Request is no longer pending"});
  db.prepare("UPDATE auth_requests SET phone_device_id=?,status='denied',used_at=? WHERE request_id=?")
    .run(phoneDeviceId,nowIso(),requestId);
  db.prepare(`INSERT INTO authentication_events
    (request_id,device_id,authentication_method,result,created_at) VALUES(?,?,?,?,?)`)
    .run(requestId,phoneDeviceId,"USER_DENIED","DENIED",nowIso());
  addSecurityEvent("DENIED","WARNING",phoneDeviceId,"Trusted phone rejected a PC unlock request.");
  io.emit("pc:access-denied",{requestId});
  res.json({ok:true});
});

app.post("/api/auth/lock", (req, res) => {
  try {
    const pcDeviceId = String(
      req.body.pcDeviceId || "BIOLOCK-PC-01"
    );

    const targetSocketId = pcAgentSockets.get(pcDeviceId);
// Persistent PC authorization state
db.prepare(`
  UPDATE pc_devices
  SET
    status='locked',
    authorized=0,
    authorized_device=NULL,
    authorized_at=NULL,
    updated_at=?
  WHERE pc_device_id=?
`).run(
  nowIso(),
  pcDeviceId
);
    // Tell the actual PC Agent to clear authorization
    if (targetSocketId) {
      const targetSocket = io.sockets.sockets.get(targetSocketId);

      if (targetSocket) {
        targetSocket.emit("pc:access-revoked", {
          pcDeviceId,
          reason: "User manually locked BioLock",
          timestamp: nowIso()
        });
      }
    }
    db.prepare(`
  UPDATE pc_devices
  SET
    authorized=0,
    authorized_device=NULL,
    authorized_at=NULL,
    updated_at=?
  WHERE pc_device_id=?
`).run(
  nowIso(),
  pcDeviceId
);
io.emit("pc:status-updated", {
  pcDeviceId,
  authorized: false,
  authorizedDevice: null,
  authorizedAt: null,
  status: "online"
});
    addSecurityEvent(
      "LOCKED",
      "INFO",
      pcDeviceId,
      "BioLock PC was manually locked by the user."
    );

    console.log("");
    console.log("=================================");
    console.log("🔒 BIOLOCK PC LOCKED");
    console.log("=================================");
    console.log("PC ID:", pcDeviceId);
    console.log("Agent Socket:", targetSocketId || "NOT FOUND");
    console.log("=================================");

    res.json({
      ok: true,
      locked: true,
      pcDeviceId
    });

  } catch (e) {
    console.error("❌ Lock error:", e);

    res.status(500).json({
      ok: false,
      error: e.message
    });
  }
});

app.post("/api/devices/pair", (req,res) => {
  const phoneDeviceId = String(req.body.phoneDeviceId || "GHANARAM-PHONE");
  ensureDevice(phoneDeviceId,"phone","Ghanaram's Phone");
  db.prepare(`INSERT OR REPLACE INTO trusted_devices
    (device_id,owner_name,authentication_method,status,paired_at)
    VALUES(?,?,?,?,?)`).run(phoneDeviceId,"Ghanaram","Passkey","trusted",nowIso());
  addSecurityEvent("PAIRING","INFO",phoneDeviceId,"Smartphone paired as a trusted device.");
  io.emit("device:paired",{deviceId:phoneDeviceId});
  res.json({ok:true});
});

app.get("/api/devices", (_,res) => {
  const devices = db.prepare(`
    SELECT d.*, t.owner_name, t.authentication_method, t.status AS trust_status
    FROM devices d LEFT JOIN trusted_devices t ON d.device_id=t.device_id
    ORDER BY d.created_at DESC`).all();
  res.json(devices);
});

// ==========================================
// DEVICE DETAILS
// ==========================================

app.get("/api/devices/:deviceId", (req, res) => {
  try {
    const deviceId = String(req.params.deviceId || "").trim();

    if (!deviceId) {
      return res.status(400).json({
        ok: false,
        error: "Missing device ID"
      });
    }

    const device = db.prepare(`
      SELECT
        d.device_id,
        d.device_type,
        d.device_name,
        d.status AS device_status,
        d.created_at,
        d.last_seen,

        t.owner_name,
        t.authentication_method,
        t.status AS trust_status,
        t.paired_at,

        CASE
          WHEN p.id IS NOT NULL THEN 1
          ELSE 0
        END AS passkey_registered

      FROM devices d

      LEFT JOIN trusted_devices t
        ON d.device_id = t.device_id

      LEFT JOIN passkeys p
        ON d.device_id = p.device_id

      WHERE d.device_id = ?

      LIMIT 1
    `).get(deviceId);

    if (!device) {
      return res.status(404).json({
        ok: false,
        error: "Device not found"
      });
    }

    let pc = null;

    if (device.device_type === "pc") {
      pc = db.prepare(`
        SELECT
          pc_device_id,
          hostname,
          platform,
          status,
          authorized,
          authorized_device,
          authorized_at,
          last_seen,
          created_at,
          updated_at
        FROM pc_devices
        WHERE pc_device_id = ?
      `).get(deviceId);
    }

    return res.json({
      ok: true,

      device: {
        deviceId: device.device_id,
        type: device.device_type,
        name: device.device_name,
        status: device.device_status,
        createdAt: device.created_at,
        lastSeen: device.last_seen,

        trust: {
          ownerName: device.owner_name || null,
          authenticationMethod:
            device.authentication_method || null,
          status: device.trust_status || null,
          pairedAt: device.paired_at || null
        },

        passkeyRegistered:
          Number(device.passkey_registered) === 1
      },

      pc: pc
        ? {
            pcDeviceId: pc.pc_device_id,
            hostname: pc.hostname,
            platform: pc.platform,
            status: pc.status,
            authorized: Number(pc.authorized) === 1,
            authorizedDevice:
              pc.authorized_device || null,
            authorizedAt:
              pc.authorized_at || null,
            lastSeen: pc.last_seen,
            createdAt: pc.created_at,
            updatedAt: pc.updated_at
          }
        : null
    });

  } catch (e) {
    console.error("❌ Device details error:", e);

    return res.status(500).json({
      ok: false,
      error: e.message
    });
  }
});

// ==================================================
// RE-TRUST DEVICE
// ==================================================

app.post("/api/devices/:deviceId/retrust", (req, res) => {
  try {
    const deviceId = String(req.params.deviceId || "").trim();

    if (!deviceId) {
      return res.status(400).json({
        ok: false,
        error: "Missing device ID",
      });
    }

    const device = db.prepare(`
      SELECT *
      FROM devices
      WHERE device_id = ?
    `).get(deviceId);

    if (!device) {
      return res.status(404).json({
        ok: false,
        error: "Device not found",
      });
    }

    const trustedDevice = db.prepare(`
      SELECT *
      FROM trusted_devices
      WHERE device_id = ?
    `).get(deviceId);

    if (!trustedDevice) {
      return res.status(404).json({
        ok: false,
        error: "Trusted device record not found",
      });
    }

    // Check whether a WebAuthn credential still exists
    const passkey = db.prepare(`
      SELECT id
      FROM passkeys
      WHERE device_id = ?
      LIMIT 1
    `).get(deviceId);

    // Restore trust
    db.prepare(`
      UPDATE trusted_devices
      SET status = 'trusted'
      WHERE device_id = ?
    `).run(deviceId);

    addSecurityEvent(
      "DEVICE_RETRUSTED",
      "INFO",
      deviceId,
      `Trusted device ${deviceId} was re-trusted.`
    );

    io.emit("device:retrusted", {
      deviceId,
      timestamp: nowIso(),
    });

    console.log("======================================");
    console.log("🔐 BIOLOCK DEVICE RE-TRUSTED");
    console.log("======================================");
    console.log("Device :", deviceId);
    console.log("Action :", "TRUST RESTORED");
    console.log(
      "Passkey:",
      passkey ? "AVAILABLE" : "NOT AVAILABLE"
    );
    console.log("======================================");

    return res.json({
      ok: true,
      retrusted: true,
      deviceId,
      passkeyAvailable: !!passkey,
      message: passkey
        ? "Trusted device re-trusted successfully"
        : "Device re-trusted, but a new passkey registration is required",
    });

  } catch (e) {
    console.error(
      "❌ Device re-trust error:",
      e
    );

    return res.status(500).json({
      ok: false,
      error: "Unable to re-trust device",
    });
  }
});

app.get("/api/pcs", (req, res) => {
  try {
    const pcs = db.prepare(`
      SELECT
        pc_device_id,
        hostname,
        platform,
        status,
        authorized,
        authorized_device,
        authorized_at,
        last_seen,
        created_at,
        updated_at
      FROM pc_devices
      ORDER BY created_at DESC
    `).all();

    res.json(pcs);

  } catch (e) {
    console.error("❌ PC list error:", e);

    res.status(500).json({
      ok: false,
      error: e.message
    });
  }
});

// ==========================================
// MANUAL PC LOCK
// ==========================================

app.post("/api/pcs/:pcDeviceId/lock", (req, res) => {
  try {
    const pcDeviceId = String(req.params.pcDeviceId || "");

    if (!pcDeviceId) {
      return res.status(400).json({
        ok: false,
        error: "Missing PC device ID",
      });
    }

    const pc = db.prepare(`
      SELECT *
      FROM pc_devices
      WHERE pc_device_id=?
    `).get(pcDeviceId);

    if (!pc) {
      return res.status(404).json({
        ok: false,
        error: "PC not found",
      });
    }

    // 1. Update DB first
    db.prepare(`
      UPDATE pc_devices
      SET
        authorized=0,
        authorized_device=NULL,
        authorized_at=NULL,
        updated_at=?
      WHERE pc_device_id=?
    `).run(
      nowIso(),
      pcDeviceId
    );

    // 2. Find connected PC Agent
    const targetSocketId =
      pcAgentSockets.get(pcDeviceId);

    if (targetSocketId) {

      const targetSocket =
        io.sockets.sockets.get(targetSocketId);

      if (targetSocket) {

        // 3. Tell PC Agent to lock
        targetSocket.emit("pc:access-revoked", {
          pcDeviceId,
          reason: "Manual lock from BioLock Dashboard",
          timestamp: nowIso(),
        });

        console.log("");
        console.log("======================================");
        console.log("🔒 BIOLOCK MANUAL LOCK");
        console.log("======================================");
        console.log("PC ID :", pcDeviceId);
        console.log("Socket:", targetSocketId);
        console.log("Action: LOCK");
        console.log("======================================");

      } else {
        console.log(
          "⚠️ PC socket unavailable:",
          pcDeviceId
        );
      }

    } else {
      console.log(
        "⚠️ No active PC Agent:",
        pcDeviceId
      );
    }

    // 4. Security event
    addSecurityEvent(
      "MANUAL_LOCK",
      "INFO",
      pcDeviceId,
      "PC manually locked from BioLock Dashboard."
    );

    // 5. Update Dashboard immediately
    io.emit("pc:status-updated", {
      pcDeviceId,
      authorized: false,
      authorizedDevice: null,
      authorizedAt: null,
      status: "online",
    });

    return res.json({
      ok: true,
      locked: true,
      pcDeviceId,
      message: "PC lock command sent",
    });

  } catch (e) {

    console.error(
      "❌ Manual PC lock error:",
      e
    );

    return res.status(500).json({
      ok: false,
      error: e.message,
    });
  }
});

// ==========================================
// REVOKE TRUSTED DEVICE
// ==========================================

app.post("/api/devices/:deviceId/revoke", (req, res) => {
  try {
    const deviceId = String(req.params.deviceId || "").trim();

    if (!deviceId) {
      return res.status(400).json({
        ok: false,
        error: "Missing device ID"
      });
    }

    const device = db.prepare(`
      SELECT *
      FROM devices
      WHERE device_id = ?
    `).get(deviceId);

    if (!device) {
      return res.status(404).json({
        ok: false,
        error: "Device not found"
      });
    }

    // Only trusted devices can be revoked
    const trustedDevice = db.prepare(`
      SELECT *
      FROM trusted_devices
      WHERE device_id = ?
    `).get(deviceId);

    if (!trustedDevice) {
      return res.status(404).json({
        ok: false,
        error: "Trusted device not found"
      });
    }

    // -----------------------------------------
    // 1. Revoke device trust
    // -----------------------------------------

    db.prepare(`
      UPDATE trusted_devices
      SET status = 'revoked'
      WHERE device_id = ?
    `).run(deviceId);


    // -----------------------------------------
    // 2. IMPORTANT:
    //    DO NOT DELETE PASSKEY
    // -----------------------------------------
    //
    // The passkey remains stored.
    // Authentication is blocked by trusted_devices.status.
    //
    // This allows:
    // Revoke → Re-Trust → Authenticate
    //
    // without registering the passkey again.


    // -----------------------------------------
    // 3. Find PCs currently authorized
    //    by this device
    // -----------------------------------------

    const authorizedPCs = db.prepare(`
      SELECT *
      FROM pc_devices
      WHERE authorized = 1
        AND authorized_device = ?
    `).all(deviceId);


    // -----------------------------------------
    // 4. Immediately invalidate active sessions
    // -----------------------------------------

    if (authorizedPCs.length > 0) {

      for (const pc of authorizedPCs) {

        db.prepare(`
          UPDATE pc_devices
          SET
            authorized = 0,
            authorized_device = NULL,
            authorized_at = NULL,
            updated_at = ?
          WHERE pc_device_id = ?
        `).run(
          nowIso(),
          pc.pc_device_id
        );


        // -------------------------------------
        // 5. Tell connected PC agent
        // -------------------------------------

       const targetSocketId = pcAgentSockets.get(pc.pc_device_id);

if (targetSocketId) {
  const targetSocket = io.sockets.sockets.get(targetSocketId);

  if (targetSocket) {
    targetSocket.emit("pc:access-revoked", {
      pcDeviceId: pc.pc_device_id,
      reason: "DEVICE_REVOKED",
      deviceId,
      timestamp: nowIso()
    });

    console.log(
      "📡 TARGETED PC REVOKE SENT:",
      pc.pc_device_id
    );
  } else {
    addSecurityEvent(
      "PC_OFFLINE",
      "WARNING",
      pc.pc_device_id,
      `PC Agent socket was not available while revoking device ${deviceId}.`
    );
  }

} else {
  addSecurityEvent(
    "PC_OFFLINE",
    "WARNING",
    pc.pc_device_id,
    `No active PC Agent connection found while revoking device ${deviceId}.`
  );
}


        // -------------------------------------
        // 6. Security event
        // -------------------------------------

        addSecurityEvent(
          "DEVICE_REVOKED",
          "CRITICAL",
          deviceId,
          `Device ${deviceId} was revoked while PC ${pc.pc_device_id} had an active authorization session. PC access was immediately revoked.`
        );


        console.log("");
        console.log("======================================");
        console.log("🔒 ACTIVE PC SESSION REVOKED");
        console.log("======================================");
        console.log("PC ID  :", pc.pc_device_id);
        console.log("Device :", deviceId);
        console.log("Reason :", "DEVICE_REVOKED");
        console.log("Action :", "ACCESS REVOKED");
        console.log("======================================");
      }

    } else {

      // No active PC session
      addSecurityEvent(
        "DEVICE_REVOKED",
        "WARNING",
        deviceId,
        `Trusted device ${deviceId} was revoked. No active PC session was using this device.`
      );

    }


    // -----------------------------------------
    // 7. Notify dashboard / mobile clients
    // -----------------------------------------

    io.emit("device:revoked", {
      deviceId,
      timestamp: nowIso()
    });


    console.log("");
    console.log("======================================");
    console.log("🚫 BIOLOCK DEVICE REVOKED");
    console.log("======================================");
    console.log("Device :", deviceId);
    console.log("Action :", "TRUST REVOKED");
    console.log("Passkey:", "PRESERVED");
    console.log("Active PCs:", authorizedPCs.length);
    console.log("======================================");


    return res.json({
      ok: true,
      revoked: true,
      deviceId,
      activeSessionsRevoked: authorizedPCs.length,
      passkeyPreserved: true,
      message:
        authorizedPCs.length > 0
          ? "Device revoked and active PC sessions terminated"
          : "Trusted device revoked successfully"
    });

  } catch (e) {

    console.error("❌ Device revoke error:", e);

    return res.status(500).json({
      ok: false,
      error: e.message
    });

  }
});

app.delete("/api/devices/:id", (req,res) => {
  const id = String(req.params.id);
  db.prepare("DELETE FROM trusted_devices WHERE device_id=?").run(id);
  addSecurityEvent("DEVICE_REMOVED","WARNING",id,"Trusted device removed.");
  io.emit("device:removed",{deviceId:id});
  res.json({ok:true});
});

app.get("/api/events", (_,res) => {
  const rows = db.prepare("SELECT * FROM authentication_events ORDER BY id DESC LIMIT 50").all();
  res.json(rows);
});

app.get("/api/security-events", (_,res) => {
  const rows = db.prepare("SELECT * FROM security_events ORDER BY id DESC LIMIT 50").all();
  res.json(rows);
});

app.post("/api/recovery", (req,res) => {
  const pin = String(req.body.pin || "");
  if (!pin || pin !== String(process.env.RECOVERY_PIN || "123456")) {
    addSecurityEvent("RECOVERY_FAILED","WARNING","BIOLOCK-PC-01","Emergency recovery attempt failed.");
    return res.status(401).json({ok:false,error:"Invalid recovery PIN"});
  }
  addSecurityEvent("RECOVERY_SUCCESS","INFO","BIOLOCK-PC-01","Emergency recovery authorization succeeded.");
  io.emit("pc:access-granted",{requestId:"RECOVERY",deviceId:"RECOVERY",method:"EMERGENCY_RECOVERY"});
  res.json({ok:true});
});

app.post("/api/demo/reset", (_,res) => {
  io.emit("demo:reset");
  addSecurityEvent("DEMO_RESET","INFO","BIOLOCK-PC-01","Competition demo state reset.");
  res.json({ok:true});
});

io.on("connection", (socket) => {

  socket.emit("server:welcome", {
    socketId: socket.id
  });

  /*
  |--------------------------------------------------------------------------
  | PHONE REQUEST
  |--------------------------------------------------------------------------
  */

  socket.on("phone:join-request", (data) => {
    io.emit("phone:join-request", data);
  });

  /*
  |--------------------------------------------------------------------------
  | SECURITY EVENT
  |--------------------------------------------------------------------------
  */

  socket.on("security:event", (data) => {
    addSecurityEvent(
      data?.type || "UNAUTHORIZED",
      data?.severity || "WARNING",
      data?.deviceId,
      data?.message || "Security event"
    );
  });
  

  /*
  |--------------------------------------------------------------------------
  | PC AGENT REGISTRATION
  |--------------------------------------------------------------------------
  */

  socket.on("pc:agent-register", (data) => {

    const pcDeviceId = String(
      data?.pcDeviceId || ""
    );

    if (!pcDeviceId) {
      console.log(
        "❌ PC Agent registration rejected: missing PC ID"
      );
      return;
    }

    const hostname = String(
      data?.hostname || pcDeviceId
    );

    const platform = String(
      data?.platform || "unknown"
    );

    /*
    |--------------------------------------------------------------------------
    | Main devices table
    |--------------------------------------------------------------------------
    */

    ensureDevice(
      pcDeviceId,
      "pc",
      hostname
    );

    /*
    |--------------------------------------------------------------------------
    | PC DEVICE RECORD
    |--------------------------------------------------------------------------
    */

    const existingPc = db.prepare(`
      SELECT *
      FROM pc_devices
      WHERE pc_device_id=?
    `).get(pcDeviceId);

    if (!existingPc) {

      db.prepare(`
        INSERT INTO pc_devices
        (
          pc_device_id,
          hostname,
          platform,
          status,
          authorized,
          authorized_device,
          authorized_at,
          last_seen,
          created_at,
          updated_at
        )
        VALUES (?,?,?,?,?,?,?,?,?,?)
      `).run(
        pcDeviceId,
        hostname,
        platform,
        "online",
        0,
        null,
        null,
        nowIso(),
        nowIso(),
        nowIso()
      );

    } else {

      /*
       * IMPORTANT:
       * Reconnecting PC should NOT automatically
       * become authorized.
       */

      db.prepare(`
        UPDATE pc_devices
        SET
          hostname=?,
          platform=?,
          status='online',
          last_seen=?,
          updated_at=?
        WHERE pc_device_id=?
      `).run(
        hostname,
        platform,
        nowIso(),
        nowIso(),
        pcDeviceId
      );
    }

    /*
    |--------------------------------------------------------------------------
    | SOCKET REPLACEMENT
    |--------------------------------------------------------------------------
    */

    const oldSocketId =
      pcAgentSockets.get(pcDeviceId);

    if (
      oldSocketId &&
      oldSocketId !== socket.id
    ) {

      console.log(
        "🔄 Replacing old PC Agent socket:",
        pcDeviceId,
        oldSocketId
      );

      const oldSocket =
        io.sockets.sockets.get(oldSocketId);

      if (oldSocket) {
        oldSocket.disconnect(true);
      }
    }

    /*
    |--------------------------------------------------------------------------
    | Store active socket
    |--------------------------------------------------------------------------
    */

    pcAgentSockets.set(
      pcDeviceId,
      socket.id
    );

    socket.pcDeviceId =
      pcDeviceId;

    /*
    |--------------------------------------------------------------------------
    | LOG
    |--------------------------------------------------------------------------
    */

    console.log("");
    console.log("=================================");
    console.log("🖥️ PC AGENT CONNECTED");
    console.log("=================================");
    console.log("PC ID   :", pcDeviceId);
    console.log("Socket  :", socket.id);
    console.log("Host    :", hostname);
    console.log("Platform:", platform);
    console.log("=================================");

    /*
    |--------------------------------------------------------------------------
    | Registration response
    |--------------------------------------------------------------------------
    */

    socket.emit(
      "pc:agent-registered",
      {
        ok: true,
        pcDeviceId,
        timestamp: nowIso()
      }
    );
    console.log("🔎 CHECKING PC STATE FROM DATABASE:", pcDeviceId);

const currentPcState = db.prepare(`
  SELECT
    authorized,
    authorized_device,
    authorized_at,
    status
  FROM pc_devices
  WHERE pc_device_id=?
`).get(pcDeviceId);

console.log("🔎 DATABASE PC STATE:", currentPcState);

if (currentPcState) {

  socket.emit("pc:state-sync", {
    pcDeviceId,

    authorized:
      Number(currentPcState.authorized) === 1,

    authorizedDevice:
      currentPcState.authorized_device || null,

    authorizedAt:
      currentPcState.authorized_at || null,

    status:
      currentPcState.status || "online",

    timestamp: nowIso()
  });

  console.log("");
  console.log("=================================");
  console.log("🔄 BIOLOCK PC STATE SYNC");
  console.log("=================================");
  console.log("PC ID :", pcDeviceId);
  console.log(
    "Authorized :",
    Number(currentPcState.authorized) === 1
  );
  console.log(
    "Device :",
    currentPcState.authorized_device || "None"
  );
  console.log(
    "Status :",
    currentPcState.status || "online"
  );
  console.log("=================================");
}
  });

  
  /*
  |--------------------------------------------------------------------------
  | PC HEARTBEAT
  |--------------------------------------------------------------------------
  */

  socket.on("pc:heartbeat", (data) => {

    const pcDeviceId = String(
      data?.pcDeviceId ||
      socket.pcDeviceId ||
      ""
    );

    if (!pcDeviceId) {
      return;
    }

    /*
    |--------------------------------------------------------------------------
    | Verify socket belongs to this PC
    |--------------------------------------------------------------------------
    */

    if (
      socket.pcDeviceId &&
      socket.pcDeviceId !== pcDeviceId
    ) {
      console.log(
        "⚠️ Invalid heartbeat PC ID:",
        pcDeviceId
      );
      return;
    }

    /*
    |--------------------------------------------------------------------------
    | Update main device
    |--------------------------------------------------------------------------
    */

    ensureDevice(
      pcDeviceId,
      "pc",
      data?.hostname || pcDeviceId
    );

    /*
    |--------------------------------------------------------------------------
    | Update PC status
    |--------------------------------------------------------------------------
    */

    db.prepare(`
      UPDATE pc_devices
      SET
        status='online',
        last_seen=?,
        updated_at=?
      WHERE pc_device_id=?
    `).run(
      nowIso(),
      nowIso(),
      pcDeviceId
    );
  });

  
  /*
  |--------------------------------------------------------------------------
  | SOCKET DISCONNECT
  |--------------------------------------------------------------------------
  */

  socket.on("disconnect", (reason) => {

    const pcDeviceId =
      socket.pcDeviceId;

    if (!pcDeviceId) {
      return;
    }

    /*
    |--------------------------------------------------------------------------
    | Only remove socket if this is
    | still the active socket
    |--------------------------------------------------------------------------
    */

    if (
      pcAgentSockets.get(pcDeviceId) ===
      socket.id
    ) {

      pcAgentSockets.delete(
        pcDeviceId
      );

      /*
      |--------------------------------------------------------------------------
      | Mark PC offline
      |--------------------------------------------------------------------------
      */

      db.prepare(`
        UPDATE pc_devices
        SET
          status='offline',
          last_seen=?,
          updated_at=?
        WHERE pc_device_id=?
      `).run(
        nowIso(),
        nowIso(),
        pcDeviceId
      );

      console.log("");
      console.log("=================================");
      console.log("🖥️ PC AGENT OFFLINE");
      console.log("=================================");
      console.log("PC ID :", pcDeviceId);
      console.log("Reason:", reason);
      console.log("=================================");
    }
  });

});

app.delete("/api/webauthn/passkey/reset", (req, res) => {
  try {
    const deviceId = String(
      req.query.deviceId || "GHANARAM-PHONE"
    );

    const result = db
      .prepare("DELETE FROM passkeys WHERE device_id = ?")
      .run(deviceId);

    console.log(
      "🗑️ Passkey reset:",
      deviceId,
      "deleted:",
      result.changes
    );

    res.json({
      success: true,
      deleted: result.changes
    });

  } catch (e) {
    console.error(e);

    res.status(500).json({
      success: false,
      error: e.message
    });
  }
});

// --------------------------------------------------
// 🔐 AUTHORIZATION SESSION MONITOR
// --------------------------------------------------

setInterval(() => {

  const expiredPcs = db.prepare(`
    SELECT
      pc_device_id,
      authorized_device,
      authorized_at
    FROM pc_devices
    WHERE authorized=1
      AND authorized_at IS NOT NULL
  `).all();

  for (const pc of expiredPcs) {

    const authorizedAt =
      new Date(pc.authorized_at).getTime();

    if (
      !authorizedAt ||
      Date.now() - authorizedAt < AUTH_SESSION_MS
    ) {
      continue;
    }

    const targetPcId = pc.pc_device_id;

    console.log("");
    console.log("======================================");
    console.log("⏰ BIOLOCK SESSION EXPIRED");
    console.log("======================================");
    console.log("PC ID  :", targetPcId);
    console.log("Device :", pc.authorized_device || "Unknown");
    console.log("Action : LOCKING PC");
    console.log("======================================");

    // Update database FIRST
    db.prepare(`
      UPDATE pc_devices
      SET
        authorized=0,
        authorized_device=NULL,
        authorized_at=NULL,
        updated_at=?
      WHERE pc_device_id=?
    `).run(
      nowIso(),
      targetPcId
    );

    // Tell connected PC Agent to lock
    const targetSocketId =
      pcAgentSockets.get(targetPcId);

    if (targetSocketId) {

      const targetSocket =
        io.sockets.sockets.get(targetSocketId);

      if (targetSocket) {

        targetSocket.emit("pc:access-revoked", {
          pcDeviceId: targetPcId,
          reason: "Authorization session expired",
          timestamp: nowIso()
        });

        console.log(
          "🔒 Expiry lock command sent to PC Agent"
        );

      }
    }

    addSecurityEvent(
      "SESSION_EXPIRED",
      "WARNING",
      targetPcId,
      "BioLock authorization session expired and PC was locked."
    );

    io.emit("pc:status-updated", {
      pcDeviceId: targetPcId,
      authorized: false,
      authorizedDevice: null,
      authorizedAt: null,
      expiresAt: null,
      status: "online"
    });
  }

}, 10_000);

server.listen(PORT,"0.0.0.0",() => {
  console.log(`BioLock server running on https://suit-entity-granny-finally.trycloudflare.com:${PORT}`);
  console.log("QR BASE URL:", PUBLIC_BASE_URL);
  console.log("MOBILE PATH:", MOBILE_PATH);
});
