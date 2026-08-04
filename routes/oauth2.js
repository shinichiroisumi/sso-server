const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const axios = require('axios');
const fs = require('fs');
const path = require('path');

const CLIENTS_FILE = path.join(__dirname, '../oauth_clients.json');

function loadClients() {
  if (!fs.existsSync(CLIENTS_FILE)) {
    return {};
  }
  try {
    return JSON.parse(fs.readFileSync(CLIENTS_FILE, 'utf8'));
  } catch {
    return {};
  }
}

function saveClients(clients) {
  fs.writeFileSync(CLIENTS_FILE, JSON.stringify(clients, null, 2));
}

const oauthClients = loadClients();

function generateClientId() {
  return crypto.randomBytes(16).toString('hex');
}

function generateClientSecret() {
  return crypto.randomBytes(32).toString('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function verifyPKCE(codeChallenge, codeChallengeMethod, codeVerifier) {
  if (!codeChallenge) {
    return true;
  }
  
  if (codeChallengeMethod === 'S256') {
    const hash = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    return hash === codeChallenge;
  }
  
  return codeVerifier === codeChallenge;
}

router.post('/clients/register', (req, res) => {
  const { client_name, redirect_uris, grant_types, response_types, scope } = req.body;
  
  if (!client_name || !redirect_uris) {
    return res.status(400).json({ error: 'client_name and redirect_uris required' });
  }
  
  const client_id = generateClientId();
  const client_secret = generateClientSecret();
  
  oauthClients[client_id] = {
    client_id: client_id,
    client_secret: client_secret,
    client_name: client_name,
    redirect_uris: redirect_uris,
    grant_types: grant_types || ['authorization_code'],
    response_types: response_types || ['code'],
    scope: scope || 'openid profile email',
    created_at: new Date().toISOString()
  };
  
  saveClients(oauthClients);
  
  res.json({
    client_id: client_id,
    client_secret: client_secret,
    client_name: client_name,
    redirect_uris: redirect_uris,
    grant_types: oauthClients[client_id].grant_types,
    response_types: oauthClients[client_id].response_types,
    scope: oauthClients[client_id].scope,
    created_at: oauthClients[client_id].created_at
  });
});

router.get('/clients/:client_id', (req, res) => {
  const { client_id } = req.params;
  const client = oauthClients[client_id];
  
  if (!client) {
    return res.status(404).json({ error: 'Client not found' });
  }
  
  res.json({
    client_id: client.client_id,
    client_name: client.client_name,
    redirect_uris: client.redirect_uris,
    grant_types: client.grant_types,
    response_types: client.response_types,
    scope: client.scope,
    created_at: client.created_at
  });
});

router.delete('/clients/:client_id', (req, res) => {
  const { client_id } = req.params;
  
  if (!oauthClients[client_id]) {
    return res.status(404).json({ error: 'Client not found' });
  }
  
  delete oauthClients[client_id];
  saveClients(oauthClients);
  res.json({ success: true });
});

const authCodes = new Map();
const refreshTokens = new Map();

router.get('/.well-known/openid-configuration', (req, res) => {
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth2/authorize`,
    token_endpoint: `${baseUrl}/oauth2/token`,
    userinfo_endpoint: `${baseUrl}/oauth2/userinfo`,
    jwks_uri: `${baseUrl}/oauth2/jwks`,
    registration_endpoint: `${baseUrl}/oauth2/clients/register`,
    response_types_supported: ['code', 'token', 'id_token', 'code token', 'code id_token', 'token id_token', 'code token id_token'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256', 'HS256'],
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'email', 'name', 'picture', 'groups']
  });
});

router.get('/jwks', (req, res) => {
  res.json({ keys: [] });
});

router.get('/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method } = req.query;
  
  if (!client_id || !oauthClients[client_id]) {
    return res.status(400).json({ error: 'Invalid client' });
  }
  
  const client = oauthClients[client_id];
  if (!client.redirect_uris.includes(redirect_uri)) {
    return res.status(400).json({ error: 'Invalid redirect_uri' });
  }
  
  if (!response_type || response_type !== 'code') {
    return res.status(400).json({ error: 'Unsupported response_type' });
  }
  
  const stateParam = state || '';
  
  const loginRedirect = `/login?redirect=${encodeURIComponent(
    `/oauth2/callback?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}&state=${encodeURIComponent(stateParam)}&code_challenge=${code_challenge || ''}&code_challenge_method=${code_challenge_method || ''}`
  )}`;
  
  res.redirect(loginRedirect);
});

router.get('/callback', async (req, res) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method } = req.query;
  
  let token = req.cookies?.sso_token;
  
  if (!token && req.query.token) {
    token = req.query.token;
  }
  
  if (!token) {
    return res.status(401).send('Not authenticated');
  }
  
  try {
    const response = await axios.post(`${req.protocol}://${req.get('host')}/api/verify/token`, {
      token: token
    });
    
    if (!response.data.valid) {
      return res.status(401).send('Invalid token');
    }
    
    const user = response.data.user;
    const code = generateToken();
    
    authCodes.set(code, {
      user: user,
      client_id: client_id,
      redirect_uri: redirect_uri,
      code_challenge: code_challenge || null,
      code_challenge_method: code_challenge_method || null,
      created_at: Date.now()
    });
    
    setTimeout(() => authCodes.delete(code), 60000);
    
    const redirectUrl = `${redirect_uri}?code=${code}&state=${state}`;
    res.redirect(redirectUrl);
    
  } catch (err) {
    res.status(500).send('Authentication failed');
  }
});

router.post('/token', (req, res) => {
  const { grant_type, code, client_id, client_secret, redirect_uri, refresh_token, code_verifier } = req.body;
  
  if (grant_type === 'authorization_code') {
    const authData = authCodes.get(code);
    
    if (!authData) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    
    if (authData.client_id !== client_id) {
      return res.status(400).json({ error: 'invalid_client' });
    }
    
    const client = oauthClients[client_id];
    if (!client || client.client_secret !== client_secret) {
      return res.status(400).json({ error: 'invalid_client' });
    }
    
    if (!verifyPKCE(authData.code_challenge, authData.code_challenge_method, code_verifier)) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    
    const accessToken = jwt.sign(
      {
        sub: authData.user.username,
        email: authData.user.email,
        name: authData.user.displayName,
        groups: authData.user.groups
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    const refreshToken = generateToken();
    refreshTokens.set(refreshToken, {
      client_id: client_id,
      user: authData.user,
      created_at: Date.now(),
      expires_in: 86400
    });
    
    setTimeout(() => refreshTokens.delete(refreshToken), 86400000);
    
    const idToken = jwt.sign(
      {
        iss: `${req.protocol}://${req.get('host')}`,
        sub: authData.user.username,
        aud: client_id,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        email: authData.user.email,
        name: authData.user.displayName
      },
      process.env.JWT_SECRET,
      { algorithm: 'HS256' }
    );
    
    authCodes.delete(code);
    
    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: refreshToken,
      id_token: idToken,
      scope: 'openid profile email'
    });
    
  } else if (grant_type === 'refresh_token') {
    const refreshData = refreshTokens.get(refresh_token);
    
    if (!refreshData) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    
    const newAccessToken = jwt.sign(
      {
        sub: refreshData.user.username,
        email: refreshData.user.email,
        name: refreshData.user.displayName,
        groups: refreshData.user.groups
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    res.json({
      access_token: newAccessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'openid profile email'
    });
    
  } else {
    res.status(400).json({ error: 'unsupported_grant_type' });
  }
});

router.get('/userinfo', (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.json({
      sub: decoded.sub,
      email: decoded.email,
      name: decoded.name,
      groups: decoded.groups || []
    });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

router.post('/revoke', (req, res) => {
  const { token } = req.body;
  
  if (!token) {
    return res.status(400).json({ error: 'token required' });
  }
  
  refreshTokens.delete(token);
  res.json({ success: true });
});

module.exports = router;