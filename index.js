const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.static("public"));

// Admin password
const ADMIN_PASSWORD = "Admin";

// In-memory stores
const userKeyMap = {}; // { userId: apiKey }
const keys = {};       // { apiKey: { userId, createdAt } }

// Middleware to check password
function checkPass(req, res, next) {
  const pw = req.headers["x-api-password"];
  if (!pw) return res.status(401).json({ error: "Missing password" });
  if (pw !== ADMIN_PASSWORD) return res.status(403).json({ error: "Invalid password" });
  next();
}

// POST /api/generate - create or return existing key with full info
app.post("/api/generate", checkPass, (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: "Missing userId" });

  // Return existing key info
  if (userKeyMap[userId]) {
    const existingKey = userKeyMap[userId];
    return res.json({
      apiKey: existingKey,
      userId,
      createdAt: keys[existingKey].createdAt,
      note: "existing"
    });
  }

  // Create new key and store data
  const apiKey = crypto.randomBytes(24).toString("hex");
  const createdAt = Date.now();

  userKeyMap[userId] = apiKey;
  keys[apiKey] = { userId, createdAt };

  res.json({ apiKey, userId, createdAt, note: "new" });
});

// POST /api/revoke - revoke key
app.post("/api/revoke", checkPass, (req, res) => {
  const { apiKey } = req.body;
  if (!keys[apiKey]) return res.status(404).json({ error: "Key not found" });

  const { userId } = keys[apiKey];
  delete keys[apiKey];
  if (userKeyMap[userId] === apiKey) delete userKeyMap[userId];

  res.json({ success: true, message: "Key revoked and removed" });
});

// GET /api/keys - list all keys with userId and createdAt
app.get("/api/keys", checkPass, (req, res) => {
  const all = Object.entries(keys).map(([key, data]) => ({
    apiKey: key,
    userId: data.userId,
    createdAt: data.createdAt
  }));
  res.json(all);
});

// Serve frontend from public folder (optional if you want UI here)
// app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
