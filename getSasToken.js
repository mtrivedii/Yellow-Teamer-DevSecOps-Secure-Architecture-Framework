const { BlobServiceClient, StorageSharedKeyCredential, generateBlobSASQueryParameters, BlobSASPermissions } = require("@azure/storage-blob");
const jwt = require('jsonwebtoken');
const path = require('path');

async function handler(req, res) {
  try {
    // CORS restricted to allowed origins
    const allowedOrigins = ['https://maanitwebapp.com', 'http://localhost:3000'];
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    // Handle OPTIONS requests
    if (req.method === 'OPTIONS') {
      return res.status(200).end();
    }

    // Authenticate via JWT cookie
    const authToken = req.cookies?.auth_token;
    if (!authToken) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
      jwt.verify(authToken, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const blobName = req.query.blobName;
    if (!blobName || typeof blobName !== 'string' || blobName.length > 256) {
      return res.status(400).json({ error: "Missing or invalid blobName query parameter" });
    }

    // Block script files by extension
    const fileExtension = path.extname(blobName).toLowerCase();
    const blockedExtensions = [
      '.js', '.jsx', '.ts', '.tsx', '.php', '.asp', '.aspx',
      '.cgi', '.pl', '.py', '.sh', '.bat', '.cmd', '.ps1',
      '.vbs', '.vbe', '.jsp', '.html', '.htm', '.exe'
    ];

    if (blockedExtensions.includes(fileExtension)) {
      console.log(`Blocked upload of script file: ${blobName}`);
      return res.status(403).json({ error: "Script files are not allowed" });
    }

    // Block script content types
    const contentType = req.query.contentType;
    const blockedContentTypes = [
      'application/javascript',
      'text/javascript',
      'application/x-javascript',
      'text/html',
      'application/xhtml+xml',
      'text/php',
      'application/x-httpd-php'
    ];

    if (contentType && blockedContentTypes.includes(contentType)) {
      console.log(`Blocked upload with script content type: ${contentType}`);
      return res.status(403).json({ error: "Script content types are not allowed" });
    }

    // Sanitize the filename
    const safeFileName = sanitizeFileName(blobName);

    const accountName = process.env.AZURE_STORAGE_ACCOUNT_NAME;
    const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY;
    const containerName = "secure-uploads";

    if (!accountName || !accountKey) {
      return res.status(500).json({ error: "Storage credentials not configured" });
    }

    // Check if container exists and create it if not
    try {
      const sharedKeyCredential = new StorageSharedKeyCredential(accountName, accountKey);
      const blobServiceClient = new BlobServiceClient(
        `https://${accountName}.blob.core.windows.net`,
        sharedKeyCredential
      );

      const containerClient = blobServiceClient.getContainerClient(containerName);

      const containerExists = await containerClient.exists();
      if (!containerExists) {
        console.log(`Creating container: ${containerName}`);
        await containerClient.create();
        await containerClient.setAccessPolicy('none');
      }
    } catch (error) {
      console.error("Error checking/creating container:", error);
    }

    const sharedKeyCredential = new StorageSharedKeyCredential(accountName, accountKey);
    const expiresOn = new Date(Date.now() + 60 * 60 * 1000);

    const sasToken = generateBlobSASQueryParameters({
      containerName,
      blobName: safeFileName,
      permissions: BlobSASPermissions.parse("cw"),
      expiresOn,
      protocol: "https"
    }, sharedKeyCredential).toString();

    const sasUrl = `https://${accountName}.blob.core.windows.net/${containerName}/${encodeURIComponent(safeFileName)}?${sasToken}`;
    return res.status(200).json({
      sasUrl,
      originalName: blobName,
      storedName: safeFileName
    });

  } catch (error) {
    console.error("Error generating SAS token:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
}

// Helper function to sanitize filenames
function sanitizeFileName(filename) {
  return filename
    .replace(/[/\\?%*:|"<>]/g, '-') // Replace illegal chars
    .replace(/\.\./g, '-')          // Prevent directory traversal
    .replace(/^\./, '-')            // No leading periods
    .trim();
}

module.exports = { handler };
