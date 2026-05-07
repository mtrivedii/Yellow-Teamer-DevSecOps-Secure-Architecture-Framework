// login.js - API endpoint for user login
const express = require('express');
const router = express.Router();
const sql = require('mssql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
// Assuming DefaultAzureCredential is used for DB connection based on original login.js
const { DefaultAzureCredential } = require('@azure/identity');

// Singleton SQL connection pool using Managed Identity
let sqlPool = null;
async function getSqlPool() {
  if (sqlPool) return sqlPool;

  try {
    console.log('[DB Connection] Attempting to get Azure SQL token via Managed Identity.');
    const credential = new DefaultAzureCredential();
    // Ensure the scope is correct for Azure SQL Database
    const tokenResponse = await credential.getToken('https://database.windows.net/.default');
    console.log('[DB Connection] Successfully obtained Azure SQL token.');

    const config = {
      server: process.env.DB_SERVER, // Ensure DB_SERVER is set in your environment
      database: process.env.DB_NAME, // Ensure DB_NAME is set in your environment
      options: {
        encrypt: true,
        trustServerCertificate: false // Should generally be false for production
      },
      authentication: {
        type: 'azure-active-directory-access-token',
        options: {
          token: tokenResponse.token
        }
      }
    };
    
    if (!config.server || !config.database) {
        console.error('FATAL ERROR: DB_SERVER or DB_NAME environment variables are not defined.');
        throw new Error('Database server or name not configured.');
    }

    sqlPool = await sql.connect(config);
    console.log('[DB Connection] SQL Pool connected successfully.');
    sqlPool.on('error', err => {
      console.error('[DB Connection] SQL Pool Error:', err.message, err.stack);
      sqlPool = null; // Reset pool on error
    });
  } catch (error) {
    console.error('[DB Connection] Failed to connect SQL Pool via Managed Identity:', error.message, error.stack);
    sqlPool = null; // Ensure pool is reset on failure
    throw error; // Re-throw error so calling function knows connection failed
  }
  return sqlPool;
}

// Rate limiting middleware
const loginAttempts = new Map();
function rateLimit(req, res, next) {
  const ip = req.ip || req.connection?.remoteAddress || 'unknown-ip';
  const now = Date.now();
  
  console.log(`[RATE LIMIT] Checking IP: ${ip}`);
  const attempts = loginAttempts.get(ip) || [];
  const recentAttempts = attempts.filter(time => now - time < 15 * 60 * 1000); // 15 minutes
  
  // Log increased from 5 to 10 as per original, consider lower for production
  if (recentAttempts.length >= 10) { 
    console.log(`[RATE LIMIT] Limit exceeded for IP: ${ip}`);
    return res.status(429).json({ 
      error: 'Too many login attempts from this IP. Please try again later.' 
    });
  }
  
  recentAttempts.push(now);
  loginAttempts.set(ip, recentAttempts);
  next();
}

// Login endpoint
router.post('/login', rateLimit, async (req, res) => {
  console.log(`[LOGIN] Received login attempt for: ${req.body.email ? req.body.email.substring(0, 3) + '***' : 'undefined_email'}`);
  
  const { email, password } = req.body;
  
  if (!email || !password) {
    console.log('[LOGIN] Missing email or password.');
    return res.status(400).json({ error: 'Email and password are required.' });
  }
  
  try {
    const pool = await getSqlPool();
    const query = `
      SELECT id, email, password, Role, status, twoFactorEnabled
      FROM dbo.users 
      WHERE email = @emailparam
    `; // Using @emailparam to avoid conflict with 'email' variable scope
    
    const result = await pool.request()
      .input('emailparam', sql.NVarChar, email)
      .query(query);
    
    if (result.recordset.length === 0) {
      console.log(`[LOGIN] Failed: User not found - ${email}`);
      await new Promise(resolve => setTimeout(resolve, Math.random() * 500 + 500)); // Timing attack mitigation
      return res.status(401).json({ error: 'Invalid email or password.' }); // Generic message
    }
    
    const user = result.recordset[0];
    console.log(`[LOGIN] User found: ${user.email}, Role: ${user.Role}, Status: ${user.status}, 2FA Enabled: ${user.twoFactorEnabled}`);
    
    if (user.status !== 'Active') {
      console.log(`[LOGIN] Login attempt for inactive/locked account: ${user.email}, Status: ${user.status}`);
      return res.status(401).json({ error: `Account is ${user.status.toLowerCase()}. Please contact support.` });
    }
    
    const passwordMatch = await bcrypt.compare(password, user.password);
    
    if (!passwordMatch) {
      console.log(`[LOGIN] Failed: Invalid password for user - ${user.email}`);
      trackUserLoginAttempts(user.email); // Track failed attempts for this specific user
      await new Promise(resolve => setTimeout(resolve, Math.random() * 500 + 500)); // Timing attack mitigation
      return res.status(401).json({ error: 'Invalid email or password.' }); // Generic message
    }
    
    // Successful password match, reset IP-based login attempts for this IP for this user.
    // This is a simple way; more complex logic might be needed for shared IPs.
    loginAttempts.delete(req.ip || req.connection?.remoteAddress || 'unknown-ip');

    if (user.twoFactorEnabled) {
      console.log(`[LOGIN] 2FA required for user: ${user.email}. Client will be redirected.`);
      // DO NOT set the final auth_token cookie here. It will be set after successful 2FA.
      return res.status(200).json({
        requireTwoFactor: true,
        userId: user.id.toString(), // Send as string if client expects that
        email: user.email,
        redirectTo: '/2fa-verify.html' // Ensure this path is correct
      });
    }
    
    // If 2FA is NOT enabled, user is fully authenticated. Generate token and set cookie.
    const sessionToken = jwt.sign(
      { 
        userId: user.id, // Keep as number if JWT standard allows and client handles
        email: user.email,
        role: user.Role 
      },
      process.env.JWT_SECRET, // Ensure JWT_SECRET is set in your environment
      { expiresIn: '1h' }
    );
    
    console.log(`[LOGIN] User successfully logged in (non-2FA path): ${user.email} (ID: ${user.id})`);
    
    // <<< SET PRODUCTION-READY COOKIE >>>
    res.cookie('auth_token', sessionToken, {
      httpOnly: true,
      secure: true, // Assuming site is HTTPS
      maxAge: 3600000, // 1 hour
      sameSite: 'lax',
      path: '/'
    });
    console.log(`[LOGIN] auth_token cookie set for user: ${user.email}`);
    
    // Update last login timestamp
    try {
      await pool.request()
        .input('userIdParam', sql.Int, user.id)
        .query(`
          UPDATE dbo.users 
          SET last_login = GETDATE() 
          WHERE id = @userIdParam
        `);
      console.log(`[LOGIN] Last login timestamp updated for user ${user.id}`);
    } catch (updateError) {
      console.error(`[LOGIN] Error updating last login for ${user.id}: ${updateError.message}`);
    }
    
    return res.status(200).json({
      message: 'Login successful',
      token: sessionToken, 
      user: {
        id: user.id.toString(), // Send as string if client expects that
        email: user.email,
        role: user.Role
      }
    });
    
  } catch (error) {
    console.error('[LOGIN] Critical error during login process:', error.message, error.stack);
    return res.status(500).json({ error: 'An internal error occurred during login. Please try again later.' });
  }
});

// Helper to track login attempts by user email (more targeted than IP for account health)
const userSpecificLoginAttempts = new Map();
function trackUserLoginAttempts(email) {
  const now = Date.now();
  const attemptsData = userSpecificLoginAttempts.get(email) || { count: 0, firstAttempt: now };
  
  // Reset count if attempts are old (e.g., older than 1 hour)
  if (now - attemptsData.firstAttempt > 60 * 60 * 1000) {
    attemptsData.count = 0;
    attemptsData.firstAttempt = now;
  }
  
  attemptsData.count++;
  userSpecificLoginAttempts.set(email, attemptsData);
  
  console.log(`[SECURITY] Failed login attempt ${attemptsData.count} for user ${email}.`);

  // Consider account locking or notification after several failed attempts (e.g., 5-10)
  if (attemptsData.count >= 10) { // Example: lock after 10 attempts
    console.warn(`[SECURITY ALERT] Account ${email} has had ${attemptsData.count} failed login attempts. Consider temporary lock.`);
    // Implement account locking logic here if desired:
    // e.g., UPDATE dbo.users SET status = 'Locked' WHERE email = @email
  }
  return attemptsData.count;
}

module.exports = router;