const os = require("os");
const { io } = require("socket.io-client");
const http = require("http");

const API =
  process.env.BIOLOCK_SERVER ||
  "https://findings-depending-takes-jelsoft.trycloudflare.com";

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
authorizedDevice = data.deviceId;
authorizationTime = data.timestamp;

  console.log("");
  console.log("=================================");
  console.log("🔓 BIOLOCK PC AUTHORIZED");
  console.log("=================================");
  console.log("Request :", data.requestId);
  console.log("Device  :", data.deviceId);
  console.log("Method  :", data.method);
  console.log("Time    :", data.timestamp);
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

  console.log("🔒 BIOLOCK PC LOCKED");
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

const STATUS_PORT = 5010;

const statusServer = http.createServer((req, res) => {
  res.setHeader("Content-Type", "application/json");

  if (req.url === "/status") {
    res.end(JSON.stringify({
      pcId: PC_ID,
      hostname: HOSTNAME,
      platform: PLATFORM,
      agentRunning: true,
      socketConnected: socket.connected,
      registered,
      authorized: pcAuthorized,
      authorizedDevice,
      authorizationTime
    }));

    return;
  }

  res.statusCode = 404;
  res.end(JSON.stringify({
    error: "Not found"
  }));
});

statusServer.listen(STATUS_PORT, "127.0.0.1", () => {
  console.log("🛡️ Local BioLock status server:", STATUS_PORT);
});

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
