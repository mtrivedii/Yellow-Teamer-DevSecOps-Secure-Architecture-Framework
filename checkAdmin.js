// checkAdmin.js
const sql = require('mssql');
const jwt = require('jsonwebtoken');
const { extractUserInfo } = require('./auth-utilities');

const sqlConfig = {
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: { type: 'azure-active-directory-msi-app-service' },
  options: { encrypt: true, trustServerCertificate: false }
};

let poolPromise = null;
function getSqlPool() {
  if (!poolPromise) {
    poolPromise = sql.connect(sqlConfig);
    poolPromise.catch(() => { poolPromise = null; }); // Reset on failure
  }
  return poolPromise;
}

async function handler(req, res) {
  console.log('Request headers:', JSON.stringify(req.headers));
  console.log('Request cookies:', JSON.stringify(req.cookies));

  // --- JWT extraction from cookie or Authorization header ---
  let authToken = req.cookies?.auth_token;
  const authHeader = req.headers.authorization;
  if (!authToken && authHeader && authHeader.startsWith('Bearer ')) {
    authToken = authHeader.split(' ')[1];
  }
  // ---------------------------------------------------------

  // Check for JWT token first
  if (authToken) {
    try {
      // Verify the JWT token
      const decodedToken = jwt.verify(authToken, process.env.JWT_SECRET); // Ensure JWT_SECRET is set in your environment
      console.log('JWT token found and verified:', decodedToken);
      
      // Check if user has admin role in the token
      if (decodedToken.role?.toLowerCase() === 'admin') {
        console.log(`Admin access granted for JWT user ${decodedToken.email}`);
        return res.status(200).json({ 
          message: 'Admin access granted',
          auth: 'JWT'
        });
      }
      
      // If role in JWT is not admin or is missing, check directly in database
      try {
        const pool = await getSqlPool();
        const request = pool.request();
        // Check by email since this is available in the JWT token
        request.input('email', sql.NVarChar, decodedToken.email);
        
        // Modified query to check by email for JWT token users
        const query = 'SELECT Role FROM Users WHERE email = @email';
        console.log(`Executing query: ${query} with email = ${decodedToken.email}`);
        
        const result = await request.query(query);
        console.log('Query result:', JSON.stringify(result.recordset));
        
        const userRole = result.recordset[0]?.Role;
        if (userRole && userRole.trim().toLowerCase() === 'admin') {
          console.log(`Admin access granted for JWT user ${decodedToken.email} via DB check`);
          return res.status(200).json({ 
            message: 'Admin access granted',
            auth: 'JWT+DB'
          });
        }
      } catch (dbError) {
        console.error('Database error during JWT user role check:', dbError);
      }
      
      // If we reach here, JWT user is not an admin
      console.warn(`Forbidden: JWT user is not an admin (email: ${decodedToken.email})`);
      return res.status(403).json({ 
        error: 'Forbidden', 
        details: 'User is not an admin',
        auth: 'JWT'
      });
      
    } catch (jwtError) {
      console.error('JWT validation error:', jwtError);
      // Continue to Azure AD check if JWT is invalid
    }
  }

  // Rest of the Azure AD auth code remains unchanged
  const userInfo = extractUserInfo(req);
  console.log(`adminCheck invoked. User ID: ${userInfo.userId || 'missing'}`);

  if (
    !userInfo.isAuthenticated ||
    !userInfo.userId ||
    typeof userInfo.userId !== 'string' ||
    userInfo.userId.length < 5
  ) {
    console.warn('Unauthorized: Missing or invalid user ID');
    return res
      .status(401)
      .json({ error: 'Unauthorized', details: 'Not authenticated or missing client principal' });
  }

  try {
    const pool = await getSqlPool();
    const request = pool.request();
    request.input('userId', sql.NVarChar, userInfo.userId);

    const query = 'SELECT Role FROM Users WHERE AzureID = @userId';
    console.log(`Executing query: ${query} with userId = ${userInfo.userId}`);

    const result = await request.query(query);
    console.log('Query result:', JSON.stringify(result.recordset));

    const userRole = result.recordset[0]?.Role;
    if (!userRole) {
      console.warn(`Forbidden: User ${userInfo.userId} not found in database`);
      return res
        .status(403)
        .json({ error: 'Forbidden', details: 'User not found in database' });
    }

    console.log(`User role found: ${userRole}`);
    if (userRole.trim().toLowerCase() === 'admin') {
      console.log(`Admin access granted for user ${userInfo.userId}`);
      return res.status(200).json({ 
        message: 'Admin access granted',
        auth: 'Azure'
      });
    }

    console.warn(`Forbidden: User ${userInfo.userId} is not an admin (role: ${userRole})`);
    return res
      .status(403)
      .json({ error: 'Forbidden', details: 'User is not an admin' });

  } catch (err) {
    console.error('Database error:', err);
    return res
      .status(500)
      .json({ error: 'Database error', details: err.message });
  }
}

module.exports = { handler };
