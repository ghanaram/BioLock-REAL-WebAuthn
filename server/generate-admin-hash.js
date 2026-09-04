const crypto = require("crypto");

const password = process.argv[2];

if (!password) {
  console.log("Usage: node generate-admin-hash.js YOUR_PASSWORD");
  process.exit(1);
}

const salt = crypto.randomBytes(16).toString("hex");

crypto.scrypt(
  password,
  salt,
  64,
  (err, derivedKey) => {
    if (err) throw err;

    console.log(
      `scrypt:${salt}:${derivedKey.toString("hex")}`
    );
  }
);