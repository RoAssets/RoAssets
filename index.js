const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.static("public"));

// Direct admin password check (plain text)
const ADMIN_PASSWORD = "Admin";

// In-memory stores
const userKeyMap = {}; // { userId: apiKey }
const keys = {};      // { apiKey: { userId, createdAt } }

function checkPass(req, res, next) {
  const pw = req.headers["x-api-password"];
  if (!pw) return res.status(401).json({ error: "Missing password" });
  if (pw !== ADMIN_PASSWORD) return res.status(403).json({ error: "Invalid password" });
  next();
}

// Generate or return existing key for a userId
app.post("/api/generate", checkPass, (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: "Missing userId" });

  // Return existing key if present
  if (userKeyMap[userId]) {
    return res.json({ apiKey: userKeyMap[userId], note: "existing" });
  }

  // Generate new key
  const apiKey = crypto.randomBytes(24).toString("hex");
  userKeyMap[userId] = apiKey;
  keys[apiKey] = { userId, createdAt: Date.now() };
  res.json({ apiKey, note: "new" });
});

// Revoke (delete) a specific apiKey
app.post("/api/revoke", checkPass, (req, res) => {
  const { apiKey } = req.body;
  if (!keys[apiKey]) return res.status(404).json({ error: "Key not found" });

  // Remove from both stores
  const { userId } = keys[apiKey];
  delete keys[apiKey];
  if (userKeyMap[userId] === apiKey) delete userKeyMap[userId];

  res.json({ success: true, message: "Key revoked and removed" });
});

// List all active keys and mappings
app.get("/api/keys", checkPass, (req, res) => {
  const all = Object.entries(keys).map(([key, data]) => ({ apiKey: key, ...data }));
  res.json(all);
});

app.listen(3000, () => console.log("Listening on port 3000"));
