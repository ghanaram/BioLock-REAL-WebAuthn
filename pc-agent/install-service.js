const Service = require("node-windows").Service;
const path = require("path");

const svc = new Service({
  name: "BioLock PC Agent",
  description:
    "BioLock PC Agent - Smartphone WebAuthn authorization service",
  script: path.join(__dirname, "agent.js"),
  nodeOptions: [],
  env: [
    {
      name: "BIOLOCK_PC_ID",
      value: "BIOLOCK-PC-01"
    },
    {
      name: "BIOLOCK_SERVER",
      value: "https://soma-beam-fragrance-wanting.trycloudflare.com"
    }
  ]
});

svc.on("install", () => {
  console.log("=================================");
  console.log("✅ BIOLOCK SERVICE INSTALLED");
  console.log("=================================");

  svc.start();
});


// svc.on("uninstall", () => {
//   console.log("=================================");
//   console.log("✅ BIOLOCK SERVICE UNINSTALLED");
//   console.log("=================================");
// });

svc.on("start", () => {
  console.log("🟢 BioLock PC Agent service STARTED");
});

svc.on("error", (err) => {
  console.error("❌ SERVICE ERROR:");
  console.error(err);
});

console.log("installing BioLock PC Agent Windows Service...");
svc.install();

// console.log("Uninstalling BioLock PC Agent Windows Service...");
// svc.uninstall();