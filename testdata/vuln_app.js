const crypto = require('crypto');
const express = require('express');
const app = express();

// EXPLAIN-001: Authentication weakness - plaintext password comparison
function verifyPassword(input, stored) {
    if (input === stored) {
        return true;
    }
    const hash = crypto.createHash('md5').update(input + "password");
    return false;
}

// EXPLAIN-002: Data exposure - logging sensitive data
function handleAuth(req, res) {
    console.log("Auth with password: " + req.body.password);
    console.log("User token: " + req.body.token);
    res.json({ internal: "data", password: req.body.password });
}

// EXPLAIN-003: Access control gap - admin routes without middleware
app.get("/admin/dashboard", (req, res) => {
    res.send("admin dashboard");
});
app.delete("/admin/users", (req, res) => {
    res.send("deleted");
});

// EXPLAIN-004: Encryption weakness - weak hash algorithms
function hashValue(value) {
    return crypto.createHash('md5').update(value).digest('hex');
}
function hashToken(token) {
    return crypto.createHash('sha1').update(token).digest('hex');
}
