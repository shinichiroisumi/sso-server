const express = require('express');
const router = express.Router();
const ActiveDirectory = require('activedirectory2');
const jwt = require('jsonwebtoken');
const ldap = require('ldapjs');
const fs = require('fs');
const path = require('path');

let tokenExpiry;

try {
  const configPath = path.join(__dirname, '../config/server.config.json');
  if (fs.existsSync(configPath)) {
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    tokenExpiry = config.auth.tokenExpiry;
    if (!tokenExpiry) {
      console.error('Error: tokenExpiry not set in config/server.config.json');
      process.exit(1);
    }
  } else {
    console.error('Error: Config file not found. Run: npm run setup');
    process.exit(1);
  }
} catch (err) {
  console.error('Error loading config:', err.message);
  process.exit(1);
}

const adConfig = {
  url: process.env.AD_URL,
  baseDN: process.env.AD_BASE_DN,
  username: process.env.AD_BIND_USER,
  password: process.env.AD_BIND_PASSWORD,
  timeout: 15000,
  connectTimeout: 15000,
  tlsOptions: { rejectUnauthorized: false },
  attributes: {
    user: ['displayName', 'mail', 'department', 'title', 'thumbnailPhoto', 'jpegPhoto', 'objectGUID', 'sAMAccountName']
  }
};

const ad = new ActiveDirectory(adConfig);

function getUserPhotoDirect(userPrincipalName, callback) {
  const client = ldap.createClient({
    url: adConfig.url,
    tlsOptions: adConfig.tlsOptions
  });
  
  client.bind(adConfig.username, adConfig.password, (err) => {
    if (err) {
      client.unbind();
      return callback(null, null);
    }
    
    const searchOptions = {
      filter: `(&(objectClass=user)(|(userPrincipalName=${userPrincipalName})(mail=${userPrincipalName})(sAMAccountName=${userPrincipalName.split('@')[0]})))`,
      scope: 'sub',
      attributes: ['thumbnailPhoto', 'jpegPhoto']
    };
    
    client.search(adConfig.baseDN, searchOptions, (err, res) => {
      if (err) {
        client.unbind();
        return callback(null, null);
      }
      
      let userFound = false;
      
      res.on('searchEntry', (entry) => {
        userFound = true;
        const photoAttr = entry.attributes.find(a => a.type === 'thumbnailPhoto') || 
                         entry.attributes.find(a => a.type === 'jpegPhoto');
        
        if (photoAttr && photoAttr.buffers && photoAttr.buffers[0]) {
          const buffer = photoAttr.buffers[0];
          const photoBase64 = `data:image/jpeg;base64,${buffer.toString('base64')}`;
          client.unbind();
          callback(null, photoBase64);
        } else {
          client.unbind();
          callback(null, null);
        }
      });
      
      res.on('error', () => {
        client.unbind();
        callback(null, null);
      });
      
      res.on('end', () => {
        if (!userFound) {
          client.unbind();
          callback(null, null);
        }
      });
    });
  });
}

router.post('/check-user', (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username required' });
  
  const userPrincipalName = username.includes('@') 
    ? username 
    : `${username}@${process.env.AD_DOMAIN}`;
  
  const opts = {
    attributes: ['displayName', 'mail', 'department', 'title', 'sAMAccountName']
  };
  
  ad.findUser(userPrincipalName, opts, (err, user) => {
    if (err || !user) {
      return res.json({ exists: false });
    }
    
    res.json({
      exists: true,
      user: {
        username: username,
        displayName: user.displayName || user.cn || username,
        email: user.mail || userPrincipalName,
        department: user.department,
        title: user.title
      }
    });
  });
});

router.post('/verify-password', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  const userPrincipalName = username.includes('@') 
    ? username 
    : `${username}@${process.env.AD_DOMAIN}`;
  
  ad.authenticate(userPrincipalName, password, (err, auth) => {
    if (err || !auth) {
      return res.status(401).json({ valid: false, error: 'Invalid credentials' });
    }
    
    getUserPhotoDirect(userPrincipalName, (photoErr, photoBase64) => {
      const opts = {
        attributes: ['displayName', 'mail', 'department', 'title']
      };
      
      ad.findUser(userPrincipalName, opts, (err, user) => {
        res.json({
          valid: true,
          user: { 
            photo: photoBase64,
            displayName: user?.displayName,
            email: user?.mail,
            department: user?.department,
            title: user?.title
          }
        });
      });
    });
  });
});

router.post('/login', (req, res) => {
  const { username, password, redirectUrl } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Логин и пароль обязательны' });
  }
  
  const userPrincipalName = username.includes('@') 
    ? username 
    : `${username}@${process.env.AD_DOMAIN}`;
  
  ad.authenticate(userPrincipalName, password, (err, auth) => {
    if (err || !auth) {
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }
    
    ad.findUser(userPrincipalName, (err, user) => {
      ad.getGroupMembershipForUser(userPrincipalName, (err, groups) => {
        const token = jwt.sign(
          {
            sub: username,
            email: user?.mail || `${username}@${process.env.AD_DOMAIN}`,
            displayName: user?.displayName || username,
            groups: groups?.map(g => g.cn) || [],
            department: user?.department,
            title: user?.title,
            userPrincipalName: userPrincipalName
          },
          process.env.JWT_SECRET,
          { expiresIn: tokenExpiry }
        );
        
        res.json({
          success: true,
          token: token,
          redirectUrl: redirectUrl || '/account'
        });
      });
    });
  });
});

router.post('/logout', (req, res) => {
  res.json({ success: true });
});

router.get('/session', (req, res) => {
  const token = req.cookies.sso_token;
  
  if (!token) {
    return res.json({ authenticated: false });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.json({
      authenticated: true,
      user: {
        username: decoded.sub,
        displayName: decoded.displayName,
        email: decoded.email,
        department: decoded.department,
        title: decoded.title
      }
    });
  } catch (err) {
    res.json({ authenticated: false });
  }
});

module.exports = router;