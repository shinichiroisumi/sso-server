const express = require('express');
const router = express.Router();
const ldap = require('ldapjs');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');

const DEVICES_FILE = path.join(__dirname, '../devices.json');
const AD_URL = process.env.AD_URL;
const AD_BASE_DN = process.env.AD_BASE_DN;
const AD_BIND_USER = process.env.AD_BIND_USER;
const AD_BIND_PASSWORD = process.env.AD_BIND_PASSWORD;
const AD_DOMAIN = process.env.AD_DOMAIN;

function loadDevices() {
  if (!fs.existsSync(DEVICES_FILE)) return {};
  return JSON.parse(fs.readFileSync(DEVICES_FILE, 'utf8'));
}

function saveDevices(devices) {
  fs.writeFileSync(DEVICES_FILE, JSON.stringify(devices, null, 2));
}

function verifyToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

function extractToken(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  return authHeader.substring(7);
}

function createADDeviceAccount(adUsername, user, deviceInfo, callback) {
  const client = ldap.createClient({
    url: AD_URL,
    tlsOptions: { rejectUnauthorized: false }
  });

  client.bind(AD_BIND_USER, AD_BIND_PASSWORD, (err) => {
    if (err) {
      client.unbind();
      return callback(err);
    }

    const computersCN = `CN=Computers,${AD_BASE_DN}`;
    const dn = `CN=${adUsername},${computersCN}`;
    const userPrincipalName = `${adUsername}@${AD_DOMAIN}`;

    const entry = {
      cn: adUsername,
      objectClass: ['top', 'person', 'organizationalPerson', 'user', 'computer'],
      sAMAccountName: `${adUsername}$`,
      userPrincipalName: userPrincipalName,
      displayName: deviceInfo.device_name || `${deviceInfo.manufacturer} ${deviceInfo.model}`,
      description: `Device: ${deviceInfo.manufacturer} ${deviceInfo.model}, Android ${deviceInfo.android_version}`,
      operatingSystem: 'Android',
      operatingSystemVersion: deviceInfo.android_version,
      name: adUsername,
      company: user.company || '',
      department: user.department || '',
      title: user.title || '',
      mail: user.email || ''
    };

    client.add(dn, entry, (err) => {
      client.unbind();
      if (err) {
        callback(err);
      } else {
        callback(null, { dn, adUsername });
      }
    });
  });
}

function deleteADDeviceAccount(adUsername, callback) {
  const client = ldap.createClient({
    url: AD_URL,
    tlsOptions: { rejectUnauthorized: false }
  });

  client.bind(AD_BIND_USER, AD_BIND_PASSWORD, (err) => {
    if (err) {
      client.unbind();
      return callback(err);
    }

    const computersCN = `CN=Computers,${AD_BASE_DN}`;
    const dn = `CN=${adUsername},${computersCN}`;

    client.del(dn, (err) => {
      client.unbind();
      callback(err);
    });
  });
}

router.post('/link-device', async (req, res) => {
  const token = extractToken(req.headers.authorization);
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const user = verifyToken(token);
  if (!user) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  const { device_uuid, manufacturer, model, android_version, sdk_version, device_name } = req.body;

  if (!device_uuid) {
    return res.status(400).json({ error: 'device_uuid required' });
  }

  const devices = loadDevices();
  if (devices[device_uuid]) {
    return res.status(409).json({ error: 'Device already linked' });
  }

  const safeUsername = user.sub.replace(/[^a-zA-Z0-9]/g, '_');
  const shortUuid = device_uuid.replace(/-/g, '').substring(0, 8);
  const adUsername = `${safeUsername}_D_${shortUuid}`;

  try {
    await new Promise((resolve, reject) => {
      createADDeviceAccount(adUsername, user, {
        manufacturer,
        model,
        android_version,
        device_name
      }, (err, result) => {
        if (err) reject(err);
        else resolve(result);
      });
    });

    devices[device_uuid] = {
      ad_username: adUsername,
      user_username: user.sub,
      user_display_name: user.displayName,
      user_email: user.email,
      manufacturer: manufacturer || '',
      model: model || '',
      android_version: android_version || '',
      sdk_version: sdk_version || '',
      device_name: device_name || `${manufacturer} ${model}`,
      linked_at: new Date().toISOString(),
      last_sync: new Date().toISOString()
    };
    saveDevices(devices);

    res.json({
      success: true,
      ad_username: adUsername,
      message: 'Device linked successfully'
    });
  } catch (err) {
    console.error('Link device error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.get('/devices', (req, res) => {
  const token = extractToken(req.headers.authorization);
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const user = verifyToken(token);
  if (!user) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  const devices = loadDevices();
  const userDevices = Object.entries(devices)
    .filter(([_, data]) => data.user_username === user.sub)
    .map(([uuid, data]) => ({
      uuid: uuid,
      ad_username: data.ad_username,
      manufacturer: data.manufacturer,
      model: data.model,
      android_version: data.android_version,
      device_name: data.device_name,
      linked_at: data.linked_at,
      last_sync: data.last_sync
    }));

  res.json({ devices: userDevices });
});

router.delete('/unlink-device', (req, res) => {
  const token = extractToken(req.headers.authorization);
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const user = verifyToken(token);
  if (!user) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  const { device_uuid } = req.body;
  if (!device_uuid) {
    return res.status(400).json({ error: 'device_uuid required' });
  }

  const devices = loadDevices();
  const device = devices[device_uuid];

  if (!device || device.user_username !== user.sub) {
    return res.status(404).json({ error: 'Device not found' });
  }

  deleteADDeviceAccount(device.ad_username, (err) => {
    if (err) {
      console.error('Failed to delete AD account:', err.message);
    }
  });

  delete devices[device_uuid];
  saveDevices(devices);

  res.json({ success: true, message: 'Device unlinked' });
});

router.get('/device-status', (req, res) => {
  const token = extractToken(req.headers.authorization);
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const user = verifyToken(token);
  if (!user) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  const { device_uuid } = req.query;
  if (!device_uuid) {
    return res.status(400).json({ error: 'device_uuid required' });
  }

  const devices = loadDevices();
  const device = devices[device_uuid];

  if (device && device.user_username === user.sub) {
    res.json({ linked: true, ad_username: device.ad_username });
  } else {
    res.json({ linked: false });
  }
});

module.exports = router;