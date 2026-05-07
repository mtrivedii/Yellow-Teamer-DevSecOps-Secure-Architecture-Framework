// register.js - API endpoint for user registration using Managed Identity for Azure SQL

const express = require('express');
const router = express.Router();
const sql = require('mssql');
const bcrypt = require('bcrypt');
const validator = require('validator');
const { DefaultAzureCredential } = require('@azure/identity');

// Singleton SQL connection pool using Managed Identity
let sqlPool = null;
async function getSqlPool() {
  if (sqlPool) return sqlPool;

  const server = process.env.DB_SERVER;
  const database = process.env.DB_NAME;

  if (!server || !database) {
    throw new Error('DB_SERVER or DB_NAME environment variables are not defined.');
  }

  // Acquire an access token for Azure SQL
  const credential = new DefaultAzureCredential();
  const tokenResponse = await credential.getToken('https://database.windows.net/.default');

  const config = {
    server,
    database,
    options: {
      encrypt: true,
      trustServerCertificate: false
    },
    authentication: {
      type: 'azure-active-directory-access-token',
      options: {
        token: tokenResponse.token
      }
    }
  };

  sqlPool = await sql.connect(config);
  return sqlPool;
}

// Validation middleware
function validateRegistration(req, res, next) {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  if (!validator.isEmail(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  if (!/[A-Z]/.test(password)) {
    return res.status(400).json({ error: 'Password must contain at least one uppercase letter' });
  }
  if (!/[a-z]/.test(password)) {
    return res.status(400).json({ error: 'Password must contain at least one lowercase letter' });
  }
  if (!/[0-9]/.test(password)) {
    return res.status(400).json({ error: 'Password must contain at least one number' });
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    return res.status(400).json({ error: 'Password must contain at least one special character' });
  }
  next();
}

// Rate limiting middleware
const registrationAttempts = new Map();
function rateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const attempts = registrationAttempts.get(ip) || [];
  const recentAttempts = attempts.filter(time => now - time < 600000);
  if (recentAttempts.length >= 5) {
    return res.status(429).json({
      error: 'Too many registration attempts. Please try again later.'
    });
  }
  recentAttempts.push(now);
  registrationAttempts.set(ip, recentAttempts);
  next();
}

// Registration endpoint
router.post('/', rateLimit, validateRegistration, async (req, res) => {
  const { email, password } = req.body;
  const normalizedEmail = email.trim().toLowerCase();
  const saltRounds = 10;

  try {
    const pool = await getSqlPool();

    // Check if email already exists
    const checkQuery = `SELECT 1 FROM dbo.users WHERE email = @email`;
    const checkResult = await pool.request()
      .input('email', sql.NVarChar, normalizedEmail)
      .query(checkQuery);

    if (checkResult.recordset.length > 0) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert user into database
    const insertQuery = `
      INSERT INTO dbo.users (
        email,
        password,
        Role,
        status,
        registration_complete
      )
      VALUES (
        @email,
        @passwordHash,
        'user',
        'Active',
        1
      );
      SELECT SCOPE_IDENTITY() AS newId;
    `;

    const result = await pool.request()
      .input('email', sql.NVarChar, normalizedEmail)
      .input('passwordHash', sql.NVarChar, hashedPassword)
      .query(insertQuery);

    const userId = result.recordset[0].newId;
    console.log(`User registered: ${normalizedEmail} (${userId})`);

    return res.status(201).json({
      message: 'Registration successful',
      email: normalizedEmail,
      userId,
      redirectTo: '/2fa.html'
    });

  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({
      error: 'An error occurred during registration'
    });
  }
});

module.exports = router;
