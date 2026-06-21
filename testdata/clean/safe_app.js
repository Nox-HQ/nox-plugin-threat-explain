const crypto = require('crypto');
const bcrypt = require('bcrypt');
const express = require('express');
const app = express();

function requireAdmin(req, res, next) {
  if (req.user && req.user.isAdmin) return next();
  return res.status(403).end();
}

// Safe: registration confirms two user inputs match — not a vuln.
function register(password, confirmPassword) {
  if (password === confirmPassword) {
    return bcrypt.hashSync(password, 10);
  }
  return null;
}

// Safe: bcrypt comparison, no plaintext credential equality.
function verifyPassword(input, storedHash) {
  return bcrypt.compareSync(input, storedHash);
}

// Safe: strong hash for non-password data.
function fingerprint(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

// Safe: admin route IS protected by authorization middleware.
app.get("/admin/dashboard", requireAdmin, (req, res) => {
  res.send("admin dashboard");
});

// Safe: no sensitive values in the log line.
function audit(userId) {
  console.log("user action", userId);
}

module.exports = { register, verifyPassword, fingerprint };
