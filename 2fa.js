// 2fa.js - API endpoint for two-factor authentication
const express = require('express');
const router = express.Router();
const sql = require('mssql');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const jwt = require('jsonwebtoken');

// Singleton SQL connection pool
let sqlPool = null;
async function getSqlPool() {
  // Using the connection string format you had in this file.
  // Ensure 'SQLAZURECONNSTR_SqlConnectionString' is correctly set in your Azure App Service environment.
  if (!sqlPool) {
    if (!process.env.SQLAZURECONNSTR_SqlConnectionString) {
      console.error('FATAL ERROR: SQLAZURECONNSTR_SqlConnectionString is not defined.');
      // In a real app, you might throw an error or have a fallback,
      // but for now, it will fail when sql.connect is called.
    }
    sqlPool = await sql.connect(process.env.SQLAZURECONNSTR_SqlConnectionString);
  }
  return sqlPool;
}

// Setup 2FA - Step 1: Generate secret and QR code
router.post('/setup', async (req, res) => {
  const { userId, email } = req.body;
  
  if (!userId || !email) {
    return res.status(400).json({ error: 'User ID and email are required' });
  }
  
  try {
    const pool = await getSqlPool();
    const userResult = await pool.request()
      .input('userId', sql.Int, userId)
      .query('SELECT id, email, twoFactorEnabled FROM dbo.users WHERE id = @userId');
    
    if (userResult.recordset.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = userResult.recordset[0];
    
    if (user.twoFactorEnabled) {
      return res.status(400).json({ error: '2FA is already enabled for this user' });
    }
    
    const secret = speakeasy.generateSecret({
      length: 20,
      name: `SecureApp:${email}` // Consider using a more generic app name if configurable
    });
    
    await pool.request()
      .input('userId', sql.Int, userId)
      .input('secret', sql.NVarChar, secret.base32)
      .query(`
        UPDATE dbo.users
        SET twoFactorTempSecret = @secret
        WHERE id = @userId
      `);
    
    const otpauth_url = secret.otpauth_url;
    const qrCodeImage = await QRCode.toDataURL(otpauth_url);
    
    console.log(`2FA setup initiated for user: ${email} (${userId})`);
    
    return res.status(200).json({
      secret: secret.base32,
      qrCodeUrl: qrCodeImage,
      message: 'Scan this QR code with your authenticator app'
    });
    
  } catch (error) {
    console.error('2FA setup error:', error.message, error.stack);
    return res.status(500).json({ error: 'Failed to set up 2FA' });
  }
});

// Setup 2FA - Step 2: Verify and activate
router.post('/verify', async (req, res) => {
  const { userId, token: verificationTokenFromUser } = req.body; // Renamed for clarity
  
  if (!userId || !verificationTokenFromUser) {
    return res.status(400).json({ error: 'User ID and verification token are required' });
  }
  
  try {
    const pool = await getSqlPool();
    const secretResult = await pool.request()
      .input('userId', sql.Int, userId)
      .query(`
        SELECT id, email, twoFactorTempSecret 
        FROM dbo.users 
        WHERE id = @userId
      `);
    
    if (secretResult.recordset.length === 0 || !secretResult.recordset[0].twoFactorTempSecret) {
      return res.status(404).json({ error: 'No 2FA setup found for this user or temporary secret missing.' });
    }
    
    const user = secretResult.recordset[0];
    
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorTempSecret,
      encoding: 'base32',
      token: verificationTokenFromUser,
      window: 1 
    });
    
    if (!verified) {
      return res.status(401).json({ error: 'Invalid verification code' });
    }
    
    const recoveryCodes = Array(3).fill(0).map(() => {
      const code = crypto.randomBytes(12).toString('hex');
      return `${code.slice(0,4)}-${code.slice(4,8)}-${code.slice(8,12)}`.toUpperCase();
    });
    
    const hashedCodes = recoveryCodes.map(code => 
      crypto.createHash('sha256').update(code).digest('hex')
    );
    
    await pool.request()
      .input('userId', sql.Int, userId)
      .input('secretToStore', sql.NVarChar, user.twoFactorTempSecret) // Store the confirmed temp secret as the main secret
      .input('recoveryCodesJson', sql.NVarChar, JSON.stringify(hashedCodes))
      .query(`
        UPDATE dbo.users
        SET 
          twoFactorEnabled = 1,
          twoFactorSecret = @secretToStore,
          twoFactorTempSecret = NULL,
          twoFactorRecoveryCodes = @recoveryCodesJson
        WHERE id = @userId
      `);
    
    console.log(`2FA activated for user: ${user.email} (${userId})`);
    
    return res.status(200).json({
      message: '2FA successfully activated',
      twoFactorEnabled: true,
      recoveryCodes: recoveryCodes // Send plain recovery codes to user once
    });
    
  } catch (error) {
    console.error('2FA verification (activation) error:', error.message, error.stack);
    return res.status(500).json({ error: 'Failed to verify 2FA token during activation' });
  }
});

// Login with 2FA (Validate 2FA code during login attempt)
router.post('/validate', async (req, res) => {
  const { userId, token: twoFactorTokenFromUser } = req.body; // Renamed for clarity
  
  if (!userId || !twoFactorTokenFromUser) {
    return res.status(400).json({ error: 'User ID and 2FA token are required' });
  }
  
  try {
    const pool = await getSqlPool();
    const secretResult = await pool.request()
      .input('userId', sql.Int, userId)
      .query(`
        SELECT id, email, twoFactorSecret, twoFactorRecoveryCodes, Role
        FROM dbo.users 
        WHERE id = @userId AND twoFactorEnabled = 1
      `);
    
    if (secretResult.recordset.length === 0 || !secretResult.recordset[0].twoFactorSecret) {
      return res.status(404).json({ error: 'No active 2FA found for this user or 2FA not enabled.' });
    }
    
    const user = secretResult.recordset[0];
    let validated = false;

    // Check if the token is a recovery code
    if (user.twoFactorRecoveryCodes) {
        try {
            const recoveryCodesList = JSON.parse(user.twoFactorRecoveryCodes); // Ensure this is an array
            const hashedTokenFromUser = crypto.createHash('sha256').update(twoFactorTokenFromUser).digest('hex');
            const recoveryCodeIndex = recoveryCodesList.indexOf(hashedTokenFromUser);

            if (recoveryCodeIndex !== -1) {
                recoveryCodesList.splice(recoveryCodeIndex, 1); // Use and invalidate
                await pool.request()
                .input('userId', sql.Int, userId)
                .input('updatedRecoveryCodes', sql.NVarChar, JSON.stringify(recoveryCodesList))
                .query(`
                    UPDATE dbo.users
                    SET twoFactorRecoveryCodes = @updatedRecoveryCodes
                    WHERE id = @userId
                `);
                validated = true;
                console.log(`2FA recovery code used for user: ${user.email} (${userId})`);
            }
        } catch (e) {
            console.error('Error parsing or using recovery codes during validation:', e.message, e.stack);
        }
    }
    
    if (!validated) { // If not validated by recovery code, try TOTP
      validated = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: twoFactorTokenFromUser,
        window: 1
      });
    }
    
    if (!validated) {
      return res.status(401).json({ error: 'Invalid verification code' });
    }
    
    console.log(`2FA validation successful for user: ${user.email} (${userId})`);
    
    const finalAuthToken = jwt.sign(
      { 
        userId: user.id,
        email: user.email,
        role: user.Role 
      },
      process.env.JWT_SECRET, // Ensure JWT_SECRET is set in your environment
      { expiresIn: '1h' }
    );
    
    // <<< SET THE AUTH_TOKEN COOKIE (PRODUCTION-READY) >>>
    res.cookie('auth_token', finalAuthToken, {
      httpOnly: true,
      secure: true, // Assuming your site is HTTPS, which it is
      maxAge: 3600000, // 1 hour
      sameSite: 'lax',
      path: '/'
    });
    
    return res.status(200).json({
      message: '2FA authentication successful',
      userId: user.id, // Or convert to string if client expects string userId
      email: user.email,
      token: finalAuthToken // Send in body for localStorage on client
    });
    
  } catch (error) {
    console.error('2FA validation (login) error:', error.message, error.stack);
    return res.status(500).json({ error: 'Failed to validate 2FA token during login' });
  }
});

// Disable 2FA
router.post('/disable', async (req, res) => {
  const { userId, token: verificationTokenFromUser } = req.body; // Renamed for clarity
  
  if (!userId) {
    return res.status(400).json({ error: 'User ID is required' });
  }
  
  try {
    const pool = await getSqlPool();
    const secretResult = await pool.request()
      .input('userId', sql.Int, userId)
      .query(`
        SELECT id, email, twoFactorSecret
        FROM dbo.users 
        WHERE id = @userId AND twoFactorEnabled = 1
      `);
    
    if (secretResult.recordset.length === 0) {
      return res.status(404).json({ error: 'No active 2FA found for this user.' });
    }
    
    const user = secretResult.recordset[0];
    
    // If token is provided for verification before disabling, verify it
    if (verificationTokenFromUser) {
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: verificationTokenFromUser,
        window: 1
      });
      
      if (!verified) {
        return res.status(401).json({ error: 'Invalid verification code for disabling 2FA' });
      }
    }
    // If no token is provided, it implies disabling without current code (e.g., admin action or after recovery)
    // Add appropriate authorization checks here if this path needs to be more secure.
    
    await pool.request()
      .input('userId', sql.Int, userId)
      .query(`
        UPDATE dbo.users
        SET 
          twoFactorEnabled = 0,
          twoFactorSecret = NULL,
          twoFactorTempSecret = NULL,
          twoFactorRecoveryCodes = NULL
        WHERE id = @userId
      `);
    
    console.log(`2FA disabled for user: ${user.email} (${userId})`);
    
    // Clear the auth_token cookie if the user is disabling their own 2FA and should be logged out
    // or forced to re-authenticate under new (non-2FA) terms.
    // This depends on your desired UX. For now, just confirming disable.
    // res.clearCookie('auth_token', { httpOnly: true, secure: true, sameSite: 'lax', path: '/' });

    return res.status(200).json({
      message: '2FA successfully disabled',
      twoFactorEnabled: false
    });
    
  } catch (error) {
    console.error('2FA disable error:', error.message, error.stack);
    return res.status(500).json({ error: 'Failed to disable 2FA' });
  }
});

// Check 2FA status
router.get('/status/:userId', async (req, res) => {
  const userIdParam = req.params.userId; // Renamed to avoid conflict
  
  if (!userIdParam) {
    return res.status(400).json({ error: 'User ID parameter is required' });
  }
  
  try {
    const pool = await getSqlPool();
    const result = await pool.request()
      .input('userIdInput', sql.Int, userIdParam) // Use a different name for input param
      .query(`
        SELECT twoFactorEnabled
        FROM dbo.users 
        WHERE id = @userIdInput
      `);
    
    if (result.recordset.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    return res.status(200).json({
      twoFactorEnabled: !!result.recordset[0].twoFactorEnabled
    });
    
  } catch (error) {
    console.error('2FA status check error:', error.message, error.stack);
    return res.status(500).json({ error: 'Failed to check 2FA status' });
  }
});

module.exports = router;