const os = require("os");
const { io } = require("socket.io-client");
const http = require("http");
const {execFile} = require("child_process");
const AGENT_PORT = 47821;


const API =
  process.env.BIOLOCK_SERVER ||
  "https://soma-beam-fragrance-wanting.trycloudflare.com";

const PC_ID =
  process.env.BIOLOCK_PC_ID ||
  "BIOLOCK-PC-01";

const HOSTNAME = os.hostname();
const PLATFORM = process.platform;

let heartbeatTimer = null;
let registered = false;
let pcAuthorized = false;
let authorizedDevice = null;
let authorizationTime = null;
let expiresAt = null;

// ==========================================
// STARTUP SECURITY
// ==========================================

// Every time the BioLock Agent starts,
// the PC begins in a protected/locked state.
// Authorization must be obtained again from
// the trusted smartphone.

function initializeSecurityState() {
  pcAuthorized = false;
  authorizedDevice = null;
  authorizationTime = null;

  console.log("");
  console.log("=================================");
  console.log("🔒 BIOLOCK STARTUP SECURITY");
  console.log("=================================");
  console.log("PC ID :", PC_ID);
  console.log("State : LOCKED");
  console.log("Auth  : NONE");
  console.log("Action: Smartphone authorization required");
  console.log("=================================");
}

initializeSecurityState();


console.log("=================================");
console.log("       BIOLOCK PC AGENT");
console.log("=================================");
console.log("Server :", API);
console.log("PC ID  :", PC_ID);
console.log("Host   :", HOSTNAME);
console.log("Platform:", PLATFORM);
console.log("Status : Connecting...");
console.log("=================================");

const socket = io(API, {
  transports: ["polling"],
  reconnection: true,
  reconnectionAttempts: Infinity,
  reconnectionDelay: 2000,
  timeout: 10000,
});

/*
|--------------------------------------------------------------------------
| CONNECTION
|--------------------------------------------------------------------------
*/

socket.on("connect", () => {
  console.log("");
  console.log("=================================");
  console.log("✅ CONNECTED TO BIOLOCK SERVER");
  console.log("=================================");
  console.log("Socket ID:", socket.id);

  registered = false;

  socket.emit("pc:agent-register", {
    pcDeviceId: PC_ID,
    hostname: HOSTNAME,
    platform: PLATFORM,
    agentVersion: "1.0.0",
  });

  startHeartbeat();
});

/*
|--------------------------------------------------------------------------
| AGENT REGISTRATION
|--------------------------------------------------------------------------
*/

socket.on("pc:agent-registered", (data) => {
  registered = true;

  console.log("");
  console.log("=================================");
  console.log("🖥️ PC AGENT REGISTERED");
  console.log("=================================");
  console.log("PC ID :", data.pcDeviceId);
  console.log("Time  :", data.timestamp);
  console.log("Status: ONLINE");
  console.log("=================================");
});
/*
|--------------------------------------------------------------------------
| PC STATE SYNC
|--------------------------------------------------------------------------
*/

socket.on("pc:state-sync", (data) => {

  const restoredAuthorized =
    Boolean(data?.authorized);

  pcAuthorized = restoredAuthorized;

  authorizedDevice =
    data?.authorizedDevice || null;

  authorizationTime =
    data?.authorizedAt || null;

  console.log("");
  console.log("=================================");
  console.log("🔄 BIOLOCK PC STATE SYNC");
  console.log("=================================");
  console.log("PC ID :", PC_ID);
  console.log(
    "Authorized :",
    pcAuthorized
  );
  console.log(
    "Device :",
    authorizedDevice || "None"
  );
  console.log(
    "Authorized At :",
    authorizationTime || "None"
  );
  console.log(
    "Status :",
    data?.status || "unknown"
  );
  console.log("=================================");

  /*
   * If server says the PC is locked,
   * enforce Windows lock locally.
   */

  if (!pcAuthorized) {

    console.log(
      "🔒 Server state = LOCKED"
    );

    lockWindows();

  } else {

    console.log(
      "🔓 Server state = AUTHORIZED"
    );

  }
});
/*
|--------------------------------------------------------------------------
| HEARTBEAT
|--------------------------------------------------------------------------
*/

function startHeartbeat() {
  stopHeartbeat();

  heartbeatTimer = setInterval(() => {
    if (!socket.connected) {
      return;
    }

    socket.emit("pc:heartbeat", {
      pcDeviceId: PC_ID,
      hostname: HOSTNAME,
      timestamp: new Date().toISOString(),
    });
  }, 15000);
}

function stopHeartbeat() {
  if (heartbeatTimer) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }
}

/*
|--------------------------------------------------------------------------
| DISCONNECT
|--------------------------------------------------------------------------
*/

socket.on("disconnect", (reason) => {
  registered = false;

  stopHeartbeat();

  console.log("");
  console.log("=================================");
  console.log("❌ DISCONNECTED FROM SERVER");
  console.log("=================================");
  console.log("Reason:", reason);
  console.log("Status: OFFLINE");
  console.log("Waiting for automatic reconnect...");
  console.log("=================================");
});

/*
|--------------------------------------------------------------------------
| CONNECTION ERROR
|--------------------------------------------------------------------------
*/

socket.on("connect_error", (error) => {
  console.log("");
  console.log("❌ CONNECTION ERROR:", error.message);
});

/*
|--------------------------------------------------------------------------
| ACCESS GRANTED
|--------------------------------------------------------------------------
*/

socket.on("pc:access-granted", (data) => {
  pcAuthorized = true;
  authorizedDevice = data?.deviceId || null;
  authorizationTime = data?.timestamp || new Date().toISOString();
  expiresAt = data?.expiresAt || null;

  console.log("");
  console.log("=================================");
  console.log("🔓 BIOLOCK PC AUTHORIZED");
  console.log("=================================");
  console.log("Request :", data?.requestId || "Unknown");
  console.log("Device  :", authorizedDevice);
    console.log("Method  :", data?.method || "Unknown");
  console.log("Time    :", authorizationTime);
  console.log("Expires :", expiresAt);
  console.log("PC ID   :", PC_ID);
  console.log("State   : AUTHORIZED");
  console.log("=================================");

  
});

/*
|--------------------------------------------------------------------------
| ACCESS DENIED
|--------------------------------------------------------------------------
*/

socket.on("pc:access-denied", (data) => {
 pcAuthorized = false;
  authorizedDevice = null;
  authorizationTime = null;
  expiresAt = null;
  console.log("");
  console.log("=================================");
  console.log("🔒 BIOLOCK PC LOCKED");
  console.log("=================================");
  console.log("Request:", data?.requestId || "Unknown");
  console.log("PC ID  :", PC_ID);
  console.log("State  : LOCKED");
  console.log("=================================");
 });

 /*
 |--------------------------------------------------------------------------
 | SERVER WELCOME
|--------------------------------------------------------------------------
*/
socket.on("server:welcome", (data) => {
  console.log("🌐 Server welcome received");
});

/*
|--------------------------------------------------------------------------
| SHUTDOWN
|--------------------------------------------------------------------------
*/

function shutdown() {
  console.log("");
  console.log("🛑 Stopping BioLock PC Agent...");

  stopHeartbeat();

  socket.disconnect();

  process.exit(0);
}

function lockWindows() {
  if (process.platform !== "win32") {
    console.log("⚠️ Windows lock is only supported on Windows.");
    return;
  }

  execFile(
    "schtasks.exe",
    [
      "/run",
      "/tn",
      "BioLock Interactive Lock"
    ],
    (error, stdout, stderr) => {

      if (error) {
        console.error(
          "❌ BioLock Windows lock failed:",
          error.message
        );

        console.error(
          "STDERR:",
          stderr
        );

        // Report lock failure to server
        socket.emit("security:event", {
          type: "WINDOWS_LOCK_FAILED",
          severity: "ERROR",
          deviceId: PC_ID,
          message:
            `Windows lock command failed for PC ${PC_ID}.`
          });

        return;
      }

      console.log("🔒 WINDOWS LOCK TASK TRIGGERED");
      console.log(
        "Interactive Windows lock requested successfully."
      );

      // Report successful Windows lock trigger
      socket.emit("security:event", {
        type: "WINDOWS_LOCK_TRIGGERED",
        severity: "INFO",
        deviceId: PC_ID,
        message:
          `Windows lock task triggered successfully for PC ${PC_ID}.`
              });
    }
  );
}


 socket.on("pc:access-revoked", (data) => {
   pcAuthorized = false;
   authorizedDevice = null;
   authorizationTime = null;
 
   console.log("");
   console.log("=================================");
   console.log("🔒 BIOLOCK AUTHORIZATION REVOKED");
   console.log("=================================");
   console.log("PC ID :", PC_ID);
   console.log("Reason:", data?.reason || "User locked PC");
   console.log("State : LOCKED");
    console.log("🚨 DEVICE REVOKE EVENT RECEIVED BY PC AGENT");
  console.log("Event Data:", data);
   console.log("=================================");
  lockWindows();

 });

const statusServer = http.createServer((req, res) => {
  if (req.url === "/status") {
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    });

    res.end(
      JSON.stringify({
        pcId: PC_ID,
        hostname: HOSTNAME,
        platform: PLATFORM,
        agentRunning: true,
        socketConnected: socket.connected,
        registered,
        pcAuthorized,
        authorizedDevice,
        authorizationTime,
        expiresAt,
      })
    );

    return;
  }

  res.writeHead(404);
  res.end("Not Found");
});

statusServer.listen(AGENT_PORT, "127.0.0.1", () => {
  console.log(
    `🌐 Agent status API: http://127.0.0.1:${AGENT_PORT}/status`
  );
});

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
