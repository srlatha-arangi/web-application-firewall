
const express = require("express");
const path = require("path");

const app = express();
const PORT = 3000;

app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  next();
});

// In-memory security logs and blocked IPs
const logs = [];
const blockedIPs = new Set();

// Simple per-IP request counter
const requests = new Map();

function logEvent(ip, url, status, reason) {
  logs.unshift({
    time: new Date().toLocaleTimeString(),
    ip,
    url,
    status,
    reason
  });

  if (logs.length > 200) logs.pop();
}

// Basic detection rules for a learning demo
function detectAttack(value) {
  const input = String(value);

  const rules = [
    { name: "SQL Injection", pattern: /(\bunion\s+select\b|\bor\b\s+['"]?\w+['"]?\s*=\s*['"]?\w+|--|;\s*drop\b)/i },
    { name: "XSS", pattern: /<\s*script\b|javascript\s*:/i },
    { name: "Path Traversal", pattern: /\.\.[/\\]/ },
    { name: "Command Injection", pattern: /;\s*(whoami|ipconfig|cmd|powershell)\b/i }
  ];

  return rules.find(rule => rule.pattern.test(input));
}

// Inspect requests before serving the dashboard
app.use((req, res, next) => {
  const ip = req.ip || req.socket.remoteAddress;
  const target = req.originalUrl;

  if (blockedIPs.has(ip)) {
    logEvent(ip, target, "BLOCKED", "IP blacklist");
    return res.status(403).send("Blocked by WAF: IP blacklisted");
  }

  const now = Date.now();
  let record = requests.get(ip);

  if (!record || now - record.start > 60000) {
    record = { start: now, count: 0 };
  }

  record.count++;
  requests.set(ip, record);

  if (record.count > 100) {
    logEvent(ip, target, "BLOCKED", "Rate limit exceeded");
    return res.status(429).send("Too many requests");
  }

  const input = decodeURIComponent(target.replace(/%(?![0-9a-f]{2})/ig, "%25"));

  const attack = detectAttack(input);

  if (attack) {
    logEvent(ip, target, "BLOCKED", attack.name);
    return res.status(403).send(
      `Request blocked by WAF: ${attack.name}`
    );
  }

  logEvent(ip, target, "ALLOWED", "No matching rule");
  next();
});

// Dashboard files
app.use(express.static(path.join(__dirname, "public")));

// Return security logs to the dashboard
app.get("/api/logs", (req, res) => {
  res.json(logs);
});

// Demo IP blacklist management
app.post("/api/block", (req, res) => {
  const ip = req.body.ip;

  if (
    typeof ip !== "string" ||
    !/^[\d.]+$/.test(ip) ||
    ip.split(".").length !== 4 ||
    ip.split(".").some(n => Number(n) > 255)
  ) {
    return res.status(400).json({ error: "Invalid IPv4 address" });
  }

  blockedIPs.add(ip);
  res.json({ message: "IP added to blacklist" });
});

app.listen(PORT, () => {
  console.log(`WAF running at http://localhost:${PORT}`);
});
