const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();

let config = {
  server: { port: 3000 },
  ad: { url: '', baseDN: '', domain: '', bindUser: '', bindPassword: '' },
  auth: { jwtSecret: 'default-secret', tokenExpiry: '8h' }
};

try {
  const configPath = path.join(__dirname, 'config', 'server.config.json');
  if (fs.existsSync(configPath)) {
    config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  } else {
    console.error('Error: Config file not found. Run: npm run setup');
    process.exit(1);
  }
} catch (err) {
  console.error('Error loading config:', err.message);
  process.exit(1);
}

const PORT = config.server.port;

app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

process.env.JWT_SECRET = config.auth.jwtSecret;
process.env.AD_URL = config.ad.url;
process.env.AD_BASE_DN = config.ad.baseDN;
process.env.AD_DOMAIN = config.ad.domain;
process.env.AD_BIND_USER = config.ad.bindUser;
process.env.AD_BIND_PASSWORD = config.ad.bindPassword;

app.use('/api/auth', require('./routes/auth'));
app.use('/api/verify', require('./routes/verify'));
app.use('/api/devices', require('./routes/devices'));

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/account', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'account.html'));
});

app.listen(PORT);