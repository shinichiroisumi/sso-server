const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const ldap = require('ldapjs');

const AD_URL = process.env.AD_URL;
const AD_BASE_DN = process.env.AD_BASE_DN;
const AD_BIND_USER = process.env.AD_BIND_USER;
const AD_BIND_PASSWORD = process.env.AD_BIND_PASSWORD;
const AD_DOMAIN = process.env.AD_DOMAIN;

function getUserPhotoDirect(userPrincipalName, callback) {
  const client = ldap.createClient({
    url: AD_URL,
    tlsOptions: { rejectUnauthorized: false }
  });
  
  client.bind(AD_BIND_USER, AD_BIND_PASSWORD, (err) => {
    if (err) {
      client.unbind();
      return callback(null, null);
    }
    
    const searchOptions = {
      filter: `(&(objectClass=user)(|(userPrincipalName=${userPrincipalName})(mail=${userPrincipalName})(sAMAccountName=${userPrincipalName.split('@')[0]})))`,
      scope: 'sub',
      attributes: ['thumbnailPhoto', 'jpegPhoto']
    };
    
    client.search(AD_BASE_DN, searchOptions, (err, res) => {
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

router.post('/token', (req, res) => {
  const { token } = req.body;
  
  if (!token) {
    return res.status(400).json({ valid: false, error: 'Token required' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    res.json({
      valid: true,
      user: {
        id: decoded.sub,
        username: decoded.sub,
        email: decoded.email,
        displayName: decoded.displayName,
        groups: decoded.groups,
        department: decoded.department,
        title: decoded.title
      },
      expiresAt: decoded.exp
    });
  } catch (err) {
    res.json({ valid: false, error: 'Invalid or expired token' });
  }
});

router.get('/me', (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Not authenticated' });
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
    res.status(401).json({ error: 'Invalid token' });
  }
});

router.get('/photo', (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const username = decoded.sub;
    const userPrincipalName = username.includes('@') 
      ? username 
      : `${username}@${AD_DOMAIN}`;
    
    getUserPhotoDirect(userPrincipalName, (photoErr, photoBase64) => {
      res.json({ photo: photoBase64 });
    });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

module.exports = router;