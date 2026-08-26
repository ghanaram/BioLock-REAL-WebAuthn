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
const ORIGIN = process.env.ORIGIN || "https://findings-depending-takes-jelsoft.trycloudflare.com";
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || ORIGIN;
const MOBILE_PATH = process.env.MOBILE_PATH || "/mobile/";

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
const addSecurityEvent = (type, severity, deviceId, message) => {
  db.prepare(`INSERT INTO security_events
    (event_type,severity,device_id,message,created_at) VALUES (?,?,?,?,?)`)
    .run(type, severity, deviceId || null, message, nowIso());
  io.emit("security:event", { type, severity, deviceId, message, createdAt: nowIso() });
};

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
    saveChallenge("registration",options.challenge);
    res.json(options);
  }catch(e){res.status(500).json({error:e.message})}
});

app.post("/api/webauthn/register/verify", async (req,res)=>{
  try{
    const deviceId=String(req.body.deviceId||"GHANARAM-PHONE");
    const response=req.body.response;
    // The challenge is extracted by SimpleWebAuthn verification from the response;
    // use the newest unconsumed registration challenge for this demo user.
    const row=db.prepare(`SELECT * FROM webauthn_challenges
      WHERE kind='registration' AND used=0 ORDER BY id DESC LIMIT 1`).get();
    if(!row || Date.now()>row.expires_at) return res.status(400).json({error:"Registration challenge expired"});
    const verification=await verifyRegistrationResponse({
      response,
      expectedChallenge:row.challenge,
      expectedOrigin:ORIGIN,
      expectedRPID:RP_ID,
      requireUserVerification:true
    });
    if(!verification.verified) return res.status(400).json({error:"Passkey registration was not verified"});
    db.prepare("UPDATE webauthn_challenges SET used=1 WHERE id=?").run(row.id);
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
        "Authentication attempted without a registered passkey."
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
    // 8. Consume challenge
    // --------------------------------------------------

    db.prepare(`
      UPDATE webauthn_challenges
      SET used=1
      WHERE id=?
    `).run(challengeRow.id);

    // --------------------------------------------------
    // 9. Update authenticator counter
    // --------------------------------------------------

    const newCounter =
      verification.authenticationInfo?.newCounter ??
      passkey.counter;

    db.prepare(`
      UPDATE passkeys
      SET counter=?
      WHERE id=?
    `).run(
      newCounter,
      passkey.id
    );

    // --------------------------------------------------
    // 10. Approve PC request
    // --------------------------------------------------

    db.prepare(`
      UPDATE auth_requests
      SET
        phone_device_id=?,
        status='approved',
        used_at=?
      WHERE request_id=?
    `).run(
      deviceId,
      nowIso(),
      requestId
    );

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

    const targetPcId = String(
  authRequest.pc_device_id || ""
);

const targetSocketId =
  pcAgentSockets.get(targetPcId);

const accessPayload = {
  requestId,
  deviceId,
  method: "WEBAUTHN_PASSKEY",
  timestamp: nowIso(),
  pcDeviceId: targetPcId,
};

if (targetSocketId) {

  const targetSocket =
    io.sockets.sockets.get(targetSocketId);

  if (targetSocket) {

    targetSocket.emit(
      "pc:access-granted",
      accessPayload
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

// app.get("/api/webauthn/auth/options", async (req,res)=>{
//   try{
//     const requestId=String(req.query.requestId||"");
//     const phoneDeviceId=String(req.query.deviceId||"GHANARAM-PHONE");
//     const row=db.prepare("SELECT * FROM auth_requests WHERE request_id=?").get(requestId);
//     if(!row) return res.status(404).json({error:"Unknown request"});
//     if(row.status!=="pending") return res.status(409).json({error:"Request is no longer pending"});
//     if(Date.now()>row.expires_at){
//       db.prepare("UPDATE auth_requests SET status='expired' WHERE request_id=?").run(requestId);
//       return res.status(410).json({error:"Authentication request expired"});
//     }
//     const passkeys=getPasskeys(phoneDeviceId);
//     if(!passkeys.length) return res.status(404).json({error:"No passkey registered for this phone"});
//     const options=await generateAuthenticationOptions({
//       rpID:RP_ID,
//       userVerification:"required",
//       allowCredentials:passkeys.map(p=>({id:p.id,transports:p.transports?JSON.parse(p.transports):undefined}))
//     });
//     saveChallenge("authentication",options.challenge,requestId);
//     res.json(options);
//   }catch(e){res.status(500).json({error:e.message})}
// });



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

  socket.on("phone:join-request", (data) => {
    io.emit("phone:join-request", data);
  });

  socket.on("security:event", (data) =>
    addSecurityEvent(
      data.type || "UNAUTHORIZED",
      data.severity || "WARNING",
      data.deviceId,
      data.message || "Security event"
    )
  );

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
      console.log("❌ PC Agent registration rejected: missing PC ID");
      return;
    }

    ensureDevice(
      pcDeviceId,
      "pc",
      data.hostname || pcDeviceId
    );

    /*
     * If the same PC reconnects,
     * replace its old socket with the new socket.
     */

    const oldSocketId =
      pcAgentSockets.get(pcDeviceId);

    if (oldSocketId && oldSocketId !== socket.id) {
      console.log(
        "🔄 Replacing old PC Agent socket:",
        pcDeviceId,
        oldSocketId
      );
    }

    pcAgentSockets.set(
      pcDeviceId,
      socket.id
    );

    /*
     * Keep PC ID attached to this socket.
     */

    socket.pcDeviceId = pcDeviceId;

    console.log("");
    console.log("=================================");
    console.log("🖥️ PC AGENT CONNECTED");
    console.log("=================================");
    console.log("PC ID   :", pcDeviceId);
    console.log("Socket  :", socket.id);
    console.log("Host    :", data.hostname || "Unknown");
    console.log("Platform:", data.platform || "Unknown");
    console.log("=================================");

    socket.emit("pc:agent-registered", {
      ok: true,
      pcDeviceId,
      timestamp: nowIso()
    });
  });

  /*
  |--------------------------------------------------------------------------
  | PC HEARTBEAT
  |--------------------------------------------------------------------------
  */

  socket.on("pc:heartbeat", (data) => {

    const pcDeviceId = String(
      data?.pcDeviceId || socket.pcDeviceId || ""
    );

    if (!pcDeviceId) {
      return;
    }

    ensureDevice(
      pcDeviceId,
      "pc",
      data?.hostname || pcDeviceId
    );
  });

  /*
  |--------------------------------------------------------------------------
  | SOCKET DISCONNECT
  |--------------------------------------------------------------------------
  */

  socket.on("disconnect", (reason) => {

    const pcDeviceId = socket.pcDeviceId;

    if (
      pcDeviceId &&
      pcAgentSockets.get(pcDeviceId) === socket.id
    ) {

      pcAgentSockets.delete(pcDeviceId);

      console.log(
        "🖥️ PC AGENT OFFLINE:",
        pcDeviceId,
        "| Reason:",
        reason
      );
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

server.listen(PORT,"0.0.0.0",() => {
  console.log(`BioLock server running on https://findings-depending-takes-jelsoft.trycloudflare.com:${PORT}`);
  console.log("QR BASE URL:", PUBLIC_BASE_URL);
  console.log("MOBILE PATH:", MOBILE_PATH);
});
