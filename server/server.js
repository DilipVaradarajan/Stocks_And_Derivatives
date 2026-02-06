require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const https = require('https');
const fs = require('fs');
const path = require('path');
const selfsigned = require('selfsigned');

const app = express();
const PORT = 5000;

// File paths
const TOKENS_FILE = path.join(__dirname, 'tokens.json');

// Schwab API URLs
const SCHWAB_AUTH_URL = 'https://api.schwabapi.com/v1/oauth/authorize';
const SCHWAB_TOKEN_URL = 'https://api.schwabapi.com/v1/oauth/token';
const SCHWAB_API_BASE = 'https://api.schwabapi.com/marketdata/v1';

// Environment variables
const CLIENT_ID = process.env.SCHWAB_CLIENT_ID;
const CLIENT_SECRET = process.env.SCHWAB_CLIENT_SECRET;
const REDIRECT_URI = process.env.SCHWAB_REDIRECT_URI || 'https://127.0.0.1:5000/callback';

// Validate environment variables
if (!CLIENT_ID || !CLIENT_SECRET) {
    console.warn('\n⚠️  WARNING: SCHWAB_CLIENT_ID and SCHWAB_CLIENT_SECRET not set');
    console.warn('   Copy .env.example to .env and add your Schwab API credentials\n');
}

// CORS configuration - allow localhost and EC2 origins
app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        // Also allow origin "null" which browsers send when opening HTML files from disk
        if (!origin || origin === 'null') return callback(null, true);

        // Allow localhost and 127.0.0.1 on any port
        if (origin.includes('127.0.0.1') || origin.includes('localhost') || origin.startsWith('file://')) {
            return callback(null, true);
        }

        // Allow EC2 public IP if configured
        const ec2Ip = process.env.EC2_PUBLIC_IP;
        if (ec2Ip && origin.includes(ec2Ip)) {
            return callback(null, true);
        }

        callback(new Error('Not allowed by CORS'));
    },
    credentials: true
}));

app.use(express.json());

// Token management functions
function loadTokens() {
    try {
        if (fs.existsSync(TOKENS_FILE)) {
            const data = fs.readFileSync(TOKENS_FILE, 'utf8');
            return JSON.parse(data);
        }
    } catch (error) {
        console.error('Error loading tokens:', error.message);
    }
    return null;
}

function saveTokens(tokens) {
    try {
        const tokenData = {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_at: Date.now() + (tokens.expires_in * 1000),
            refresh_expires_at: Date.now() + (7 * 24 * 60 * 60 * 1000) // 7 days
        };
        fs.writeFileSync(TOKENS_FILE, JSON.stringify(tokenData, null, 2));
        console.log('Tokens saved successfully');
        return tokenData;
    } catch (error) {
        console.error('Error saving tokens:', error.message);
        throw error;
    }
}

function clearTokens() {
    try {
        if (fs.existsSync(TOKENS_FILE)) {
            fs.unlinkSync(TOKENS_FILE);
        }
    } catch (error) {
        console.error('Error clearing tokens:', error.message);
    }
}

async function refreshAccessToken() {
    const tokens = loadTokens();
    if (!tokens || !tokens.refresh_token) {
        throw new Error('No refresh token available');
    }

    // Check if refresh token is expired (7 days)
    if (Date.now() > tokens.refresh_expires_at) {
        clearTokens();
        throw new Error('Refresh token expired - please re-authenticate');
    }

    try {
        const credentials = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

        const response = await axios.post(SCHWAB_TOKEN_URL,
            new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: tokens.refresh_token
            }).toString(),
            {
                headers: {
                    'Authorization': `Basic ${credentials}`,
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );

        const newTokens = saveTokens(response.data);
        console.log('Access token refreshed successfully');
        return newTokens;
    } catch (error) {
        console.error('Error refreshing token:', error.response?.data || error.message);
        clearTokens();
        throw new Error('Failed to refresh token - please re-authenticate');
    }
}

async function getValidAccessToken() {
    let tokens = loadTokens();

    if (!tokens) {
        throw new Error('Not authenticated - please login first');
    }

    // Check if access token is expired or will expire in the next 5 minutes
    const bufferTime = 5 * 60 * 1000; // 5 minutes
    if (Date.now() + bufferTime > tokens.expires_at) {
        console.log('Access token expired or expiring soon, refreshing...');
        tokens = await refreshAccessToken();
    }

    return tokens.access_token;
}

// ============================================
// OAuth2 Routes
// ============================================

// GET /auth/login - Redirect user to Schwab login
app.get('/auth/login', (req, res) => {
    if (!CLIENT_ID) {
        return res.status(500).send(`
            <h1>Configuration Error</h1>
            <p>SCHWAB_CLIENT_ID is not set. Please:</p>
            <ol>
                <li>Copy server/.env.example to server/.env</li>
                <li>Add your Schwab API credentials</li>
                <li>Restart the server</li>
            </ol>
        `);
    }

    const authUrl = new URL(SCHWAB_AUTH_URL);
    authUrl.searchParams.set('client_id', CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
    authUrl.searchParams.set('response_type', 'code');

    console.log('Redirecting to Schwab login...');
    res.redirect(authUrl.toString());
});

// GET /callback - Handle OAuth callback
app.get('/callback', async (req, res) => {
    const { code, error, error_description } = req.query;

    if (error) {
        console.error('OAuth error:', error, error_description);
        return res.status(400).send(`
            <h1>Authentication Error</h1>
            <p>${error}: ${error_description || 'Unknown error'}</p>
            <a href="/auth/login">Try again</a>
        `);
    }

    if (!code) {
        return res.status(400).send(`
            <h1>Error</h1>
            <p>No authorization code received</p>
            <a href="/auth/login">Try again</a>
        `);
    }

    try {
        const credentials = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

        const response = await axios.post(SCHWAB_TOKEN_URL,
            new URLSearchParams({
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: REDIRECT_URI
            }).toString(),
            {
                headers: {
                    'Authorization': `Basic ${credentials}`,
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );

        saveTokens(response.data);

        res.send(`
            <html>
            <head>
                <style>
                    body { font-family: system-ui; background: #0a0e27; color: #e8eaf6; padding: 2rem; text-align: center; }
                    h1 { color: #10b981; }
                    p { margin: 1rem 0; }
                    .note { color: #9ca3af; font-size: 0.9rem; }
                </style>
            </head>
            <body>
                <h1>Authentication Successful!</h1>
                <p>You can now close this window and use the Derivatives Analytics app.</p>
                <p class="note">Your session will last 30 minutes before auto-refreshing.</p>
            </body>
            </html>
        `);
    } catch (error) {
        console.error('Token exchange error:', error.response?.data || error.message);
        res.status(500).send(`
            <h1>Token Exchange Failed</h1>
            <p>${error.response?.data?.error_description || error.message}</p>
            <a href="/auth/login">Try again</a>
        `);
    }
});

// GET /auth/status - Check authentication status
app.get('/auth/status', (req, res) => {
    const tokens = loadTokens();

    if (!tokens) {
        return res.json({ authenticated: false, reason: 'No tokens found' });
    }

    // Check if refresh token is expired
    if (Date.now() > tokens.refresh_expires_at) {
        clearTokens();
        return res.json({ authenticated: false, reason: 'Session expired - please login again' });
    }

    // Check if access token is still valid
    const accessTokenValid = Date.now() < tokens.expires_at;

    res.json({
        authenticated: true,
        accessTokenValid,
        expiresAt: new Date(tokens.expires_at).toISOString(),
        refreshExpiresAt: new Date(tokens.refresh_expires_at).toISOString()
    });
});

// POST /auth/logout - Clear stored tokens
app.post('/auth/logout', (req, res) => {
    clearTokens();
    res.json({ success: true, message: 'Logged out successfully' });
});

// ============================================
// Market Data API Routes
// ============================================

// GET /api/quote/:symbol - Get stock quote
app.get('/api/quote/:symbol', async (req, res) => {
    const { symbol } = req.params;

    try {
        const accessToken = await getValidAccessToken();

        const response = await axios.get(`${SCHWAB_API_BASE}/quotes`, {
            params: {
                symbols: symbol.toUpperCase(),
                fields: 'quote,fundamental'
            },
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Accept': 'application/json'
            }
        });

        res.json(response.data);
    } catch (error) {
        console.error('Quote API error:', error.response?.data || error.message);

        if (error.message.includes('Not authenticated') || error.message.includes('re-authenticate')) {
            return res.status(401).json({
                error: 'Authentication required',
                message: error.message,
                loginUrl: '/auth/login'
            });
        }

        res.status(error.response?.status || 500).json({
            error: 'Failed to fetch quote',
            message: error.response?.data?.message || error.message
        });
    }
});

// GET /api/options/:symbol - Get options chain
app.get('/api/options/:symbol', async (req, res) => {
    const { symbol } = req.params;
    const {
        contractType = 'ALL',
        strikeCount = 25,
        includeUnderlyingQuote = 'true',
        fromDate,
        toDate
    } = req.query;

    try {
        const accessToken = await getValidAccessToken();

        const params = {
            symbol: symbol.toUpperCase(),
            contractType,
            strikeCount: parseInt(strikeCount),
            includeUnderlyingQuote: includeUnderlyingQuote === 'true'
        };

        // Add optional date filters
        if (fromDate) params.fromDate = fromDate;
        if (toDate) params.toDate = toDate;

        const response = await axios.get(`${SCHWAB_API_BASE}/chains`, {
            params,
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Accept': 'application/json'
            }
        });

        res.json(response.data);
    } catch (error) {
        console.error('Options API error:', error.response?.data || error.message);

        if (error.message.includes('Not authenticated') || error.message.includes('re-authenticate')) {
            return res.status(401).json({
                error: 'Authentication required',
                message: error.message,
                loginUrl: '/auth/login'
            });
        }

        res.status(error.response?.status || 500).json({
            error: 'Failed to fetch options chain',
            message: error.response?.data?.message || error.message
        });
    }
});

// Serve the frontend app
app.get('/app', (req, res) => {
    const frontendPath = path.join(__dirname, 'frontend.html');
    if (fs.existsSync(frontendPath)) {
        res.sendFile(frontendPath);
    } else {
        res.status(404).send('Frontend not found');
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        configured: !!(CLIENT_ID && CLIENT_SECRET),
        timestamp: new Date().toISOString()
    });
});

// Root endpoint - show status
app.get('/', (req, res) => {
    const tokens = loadTokens();
    const isAuthenticated = tokens && Date.now() < tokens.refresh_expires_at;

    res.send(`
        <html>
        <head>
            <style>
                body { font-family: system-ui; background: #0a0e27; color: #e8eaf6; padding: 2rem; max-width: 800px; margin: 0 auto; }
                h1 { color: #6366f1; }
                .status { padding: 1rem; border-radius: 8px; margin: 1rem 0; }
                .success { background: rgba(16, 185, 129, 0.2); border: 1px solid #10b981; }
                .warning { background: rgba(251, 191, 36, 0.2); border: 1px solid #fbbf24; }
                .error { background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; }
                a { color: #6366f1; }
                code { background: rgba(255,255,255,0.1); padding: 0.2rem 0.5rem; border-radius: 4px; }
            </style>
        </head>
        <body>
            <h1>Schwab API Server</h1>

            <div class="status ${CLIENT_ID && CLIENT_SECRET ? 'success' : 'error'}">
                <strong>API Credentials:</strong> ${CLIENT_ID && CLIENT_SECRET ? 'Configured' : 'Not configured - check .env file'}
            </div>

            <div class="status ${isAuthenticated ? 'success' : 'warning'}">
                <strong>Authentication:</strong> ${isAuthenticated ? 'Logged in' : 'Not logged in'}
                ${!isAuthenticated ? '<br><a href="/auth/login">Click here to login with Schwab</a>' : ''}
            </div>

            <h2>Available Endpoints</h2>
            <ul>
                <li><code>GET /auth/login</code> - Start OAuth login</li>
                <li><code>GET /auth/status</code> - Check auth status</li>
                <li><code>POST /auth/logout</code> - Logout</li>
                <li><code>GET /api/quote/:symbol</code> - Get stock quote</li>
                <li><code>GET /api/options/:symbol</code> - Get options chain</li>
            </ul>
        </body>
        </html>
    `);
});

// Generate self-signed certificate for HTTPS
function generateCertificate() {
    const certPath = path.join(__dirname, 'cert.pem');
    const keyPath = path.join(__dirname, 'key.pem');

    // Check if certs already exist
    if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
        return {
            cert: fs.readFileSync(certPath),
            key: fs.readFileSync(keyPath)
        };
    }

    const ec2Ip = process.env.EC2_PUBLIC_IP;
    const commonName = ec2Ip || '127.0.0.1';

    console.log(`Generating self-signed certificate for ${commonName}...`);
    const attrs = [{ name: 'commonName', value: commonName }];

    const altNames = [
        { type: 2, value: 'localhost' },
        { type: 7, ip: '127.0.0.1' }
    ];

    // Include EC2 public IP in SAN if configured
    if (ec2Ip) {
        altNames.push({ type: 7, ip: ec2Ip });
    }

    const pems = selfsigned.generate(attrs, {
        algorithm: 'sha256',
        days: 365,
        keySize: 2048,
        extensions: [
            { name: 'basicConstraints', cA: true },
            {
                name: 'subjectAltName',
                altNames
            }
        ]
    });

    fs.writeFileSync(certPath, pems.cert);
    fs.writeFileSync(keyPath, pems.private);

    return {
        cert: pems.cert,
        key: pems.private
    };
}

// Start HTTPS server
const { cert, key } = generateCertificate();
const httpsServer = https.createServer({ cert, key }, app);

// Bind to 0.0.0.0 when deployed on EC2, otherwise localhost only
const BIND_HOST = process.env.EC2_PUBLIC_IP ? '0.0.0.0' : '127.0.0.1';
const DISPLAY_HOST = process.env.EC2_PUBLIC_IP || '127.0.0.1';

httpsServer.listen(PORT, BIND_HOST, () => {
    console.log('\n========================================');
    console.log('  Schwab API Server');
    console.log('========================================');
    console.log(`  Server running at: https://${DISPLAY_HOST}:${PORT}`);
    console.log(`  Bound to:          ${BIND_HOST}:${PORT}`);
    console.log(`  OAuth callback:    ${REDIRECT_URI}`);
    console.log('');
    if (!CLIENT_ID || !CLIENT_SECRET) {
        console.log('  ⚠️  Credentials not configured!');
        console.log('  Copy .env.example to .env and add your API keys');
    } else {
        console.log('  ✓ Credentials configured');
    }
    console.log('========================================\n');
});
