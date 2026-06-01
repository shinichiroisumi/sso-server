#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { execSync } = require('child_process');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const question = (query) => new Promise(resolve => rl.question(query, resolve));

async function main() {
  console.log('\n========================================');
  console.log('SSO Server Setup');
  console.log('========================================\n');

  console.log('[1/5] Installing dependencies...');
  execSync('npm install', { stdio: 'inherit' });
  console.log('Dependencies installed\n');

  console.log('[2/5] Configuring Active Directory...\n');

  const domain = await question('Domain (example: company.local): ');
  const adminUser = await question('Administrator username: ');
  const adminPassword = await question('Administrator password: ');

  const baseDN = domain.split('.').map(part => `dc=${part}`).join(',');
  const bindUser = `cn=${adminUser},cn=Users,${baseDN}`;

  const config = {
    server: {
      port: 3000
    },
    ad: {
      url: `ldaps://${domain.toLowerCase()}:636`,
      baseDN: baseDN,
      domain: domain.toLowerCase(),
      bindUser: bindUser,
      bindPassword: adminPassword
    },
    auth: {
      jwtSecret: require('crypto').randomBytes(64).toString('hex'),
      tokenExpiry: '8h'
    }
  };

  const configDir = path.join(__dirname, 'config');
  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir);
  }

  const configPath = path.join(configDir, 'server.config.json');
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  console.log('\nConfiguration saved to config/server.config.json\n');

  console.log('[3/5] Creating start script...');
  createStartScript();
  console.log('Start script created\n');

  console.log('[4/5] Testing AD connection...');
  const adTest = await testADConnection(config.ad);
  if (adTest.success) {
    console.log('AD connection successful\n');
  } else {
    console.log('AD connection failed:', adTest.error);
    process.exit(1);
  }

  console.log('[5/5] Creating systemd service...\n');
  const createService = await question('Create systemd service for auto-start? (y/n): ');
  
  if (createService.toLowerCase() === 'y') {
    await createSystemdService();
    console.log('Systemd service created\n');
  }

  console.log('Setup complete!\n');
  console.log('To start server: npm start');
  console.log('Login page: http://localhost:3000/login');
  console.log('To run as service: sudo systemctl start sso-server\n');

  rl.close();
}

async function testADConnection(adConfig) {
  const ldap = require('ldapjs');
  const client = ldap.createClient({
    url: adConfig.url,
    tlsOptions: { rejectUnauthorized: false }
  });

  return new Promise((resolve) => {
    client.bind(adConfig.bindUser, adConfig.bindPassword, (err) => {
      if (err) {
        resolve({ success: false, error: err.message });
      } else {
        resolve({ success: true });
      }
      client.unbind();
    });
  });
}

function createStartScript() {
  const startScript = `#!/bin/bash
cd ${__dirname}
node app.js
`;

  const scriptPath = path.join(__dirname, 'start.sh');
  fs.writeFileSync(scriptPath, startScript);
  fs.chmodSync(scriptPath, 0o755);
}

async function createSystemdService() {
  const serviceContent = `[Unit]
Description=SSO Enterprise Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${__dirname}
ExecStart=${__dirname}/start.sh
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
`;

  const servicePath = '/etc/systemd/system/sso-server.service';
  
  try {
    fs.writeFileSync(servicePath, serviceContent);
    execSync('sudo systemctl daemon-reload', { stdio: 'inherit' });
  } catch (err) {
    console.log('Could not create systemd service. Run with sudo: node setup.js');
  }
}

if (require.main === module) {
  main().catch(console.error);
}