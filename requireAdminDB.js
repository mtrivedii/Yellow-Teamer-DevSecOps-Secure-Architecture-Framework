// requireAdminDb.js
const sql = require('mssql');
const path = require('path');
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
    poolPromise.catch(() => { poolPromise = null; });
  }
  return poolPromise;
}

async function requireAdminDb(req, res, next) {
  console.log('--- ADMIN DB MIDDLEWARE DEBUG ---');
  
  // Check for JWT token first
  const authToken = req.cookies?.auth_token;
  if (authToken) {
    try {
      // Verify the JWT token
      const decodedToken = jwt.verify(authToken, process.env.JWT_SECRET); // Ensure JWT_SECRET is set in your environment
      console.log('JWT token found and verified:', decodedToken);
      
      // Check if user has admin role in the token
      if (decodedToken.role?.toLowerCase() === 'admin') {
        console.log('Admin access granted via JWT token');
        req.userRole = decodedToken.role;
        return next();
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
        console.log('DB result:', JSON.stringify(result.recordset));
        
        const userRole = result.recordset[0]?.Role;
        if (userRole && userRole.trim().toLowerCase() === 'admin') {
          console.log(`Admin access granted for JWT user ${decodedToken.email} via DB check`);
          req.userRole = userRole;
          return next();
        }
      } catch (dbError) {
        console.error('Database error during JWT user role check:', dbError);
      }
      
      // If we reach here, JWT user is not an admin
      console.warn('Forbidden: JWT user is not admin (email:', decodedToken.email, ')');
      return res.status(401).sendFile(path.join(__dirname, 'public', '401.html'));
    } catch (jwtError) {
      console.error('JWT validation error:', jwtError);
      // Continue to Azure AD check if JWT is invalid
    }
  }

  // Rest of the Azure AD auth code remains unchanged
  const userInfo = extractUserInfo(req);
  console.log('userInfo from Azure AD:', userInfo);

  if (
    !userInfo.isAuthenticated ||
    !userInfo.userId ||
    typeof userInfo.userId !== 'string' ||
    userInfo.userId.length < 5
  ) {
    console.warn('Unauthorized: Missing or invalid user ID');
    return res
      .status(401)
      .sendFile(path.join(__dirname, 'public', '401.html'));
  }

  try {
    const pool = await getSqlPool();
    const request = pool.request();
    request.input('userId', sql.NVarChar, userInfo.userId);

    console.log('Querying DB with AzureID:', userInfo.userId);

    const result = await request.query(
      'SELECT Role FROM Users WHERE AzureID = @userId'
    );
    console.log('DB result:', result.recordset);

    const userRole = result.recordset[0]?.Role;
    if (!userRole) {
      console.warn('Forbidden: User not found in database');
      return res
        .status(401)
        .sendFile(path.join(__dirname, 'public', '401.html'));
    }

    console.log('User role found:', userRole);

    if (userRole.trim().toLowerCase() !== 'admin') {
      console.warn('Forbidden: User is not admin (role:', userRole, ')');
      return res
        .status(401)
        .sendFile(path.join(__dirname, 'public', '401.html'));
    }

    // User is admin
    req.userRole = userRole;
    next();
  } catch (err) {
    console.error('Database error in requireAdminDb:', err);
    return res.status(500).send('Internal Server Error');
  }
}

module.exports = requireAdminDb;