const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const forge = require('node-forge');
const secrets = require('secrets.js');

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'CHANGE_THIS_TO_SOMETHING_SECURE',
  resave: false,
  saveUninitialized: true
}));

const upload = multer({ dest: path.join(__dirname, 'uploads') });

const db = new sqlite3.Database('secure_file.db');
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      six_digit_id TEXT UNIQUE NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      public_key_pem TEXT,
      private_key_pem TEXT
    )
  `);
});

function dbRun(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve(this.lastID);
    });
  });
}
function dbGet(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}
function dbAll(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

function generateSixDigitID() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function generateRSAKeyPair(bits=2048) {
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair({ bits, workers: -1 }, (err, keypair) => {
      if (err) return reject(err);
      const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
      const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
      resolve({ privateKeyPem, publicKeyPem });
    });
  });
}

function hashPassword(password) {
  const salt = bcrypt.genSaltSync(10);
  return bcrypt.hashSync(password, salt);
}
function checkPassword(storedHash, candidate) {
  return bcrypt.compareSync(candidate, storedHash);
}

function aesEncrypt(dataBuf, keyBuf) {
  const iv = forge.random.getBytesSync(12); // GCM recommended 96-bit IV
  const cipher = forge.cipher.createCipher('AES-GCM', keyBuf.toString('binary'));
  cipher.start({ iv });
  cipher.update(forge.util.createBuffer(dataBuf));
  cipher.finish();
  const enc = cipher.output.getBytes();
  const tag = cipher.mode.tag.getBytes();
  return {
    ciphertext: Buffer.from(enc, 'binary'),
    iv: Buffer.from(iv, 'binary'),
    tag: Buffer.from(tag, 'binary')
  };
}

function aesDecrypt(ciphertextBuf, keyBuf, ivBuf, tagBuf) {
  const decipher = forge.cipher.createDecipher('AES-GCM', keyBuf.toString('binary'));
  decipher.start({
    iv: ivBuf.toString('binary'),
    tag: forge.util.createBuffer(tagBuf.toString('binary'))
  });
  decipher.update(forge.util.createBuffer(ciphertextBuf));
  const pass = decipher.finish();
  if (!pass) throw new Error("AES-GCM authentication failed");
  const plain = decipher.output.getBytes();
  return Buffer.from(plain, 'binary');
}

function rsaEncrypt(publicKeyPem, dataBuf) {
  const pubKey = forge.pki.publicKeyFromPem(publicKeyPem);
  const encrypted = pubKey.encrypt(dataBuf.toString('binary'), 'RSA-OAEP', {
    md: forge.md.sha256.create()
  });
  return Buffer.from(encrypted, 'binary');
}

function rsaDecrypt(privateKeyPem, encBuf) {
  const privKey = forge.pki.privateKeyFromPem(privateKeyPem);
  const decrypted = privKey.decrypt(encBuf.toString('binary'), 'RSA-OAEP', {
    md: forge.md.sha256.create()
  });
  return Buffer.from(decrypted, 'binary');
}

function splitSecret(keyHex, totalShares, threshold) {
  return secrets.share(keyHex, totalShares, threshold);
}
function recoverSecret(sharesArr) {
  return secrets.combine(sharesArr);
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

const globalDecryptionPool = {};

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'home.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'register.html'));
});

app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.send("Username & password required. <a href='/register'>Back</a>");
    }
    const sixDigit = generateSixDigitID();
    const { privateKeyPem, publicKeyPem } = await generateRSAKeyPair();
    const passHash = hashPassword(password);
    await dbRun(`
      INSERT INTO users (six_digit_id, username, password_hash, public_key_pem, private_key_pem)
      VALUES (?, ?, ?, ?, ?)
    `, [sixDigit, username, passHash, publicKeyPem, privateKeyPem]);

    res.send(`
      <h2>Registration Successful</h2>
      <p>Your 6-digit ID: <b>${sixDigit}</b></p>
      <p><a href="/login">Login</a></p>
    `);
  } catch (err) {
    console.error(err);
    res.send("Error registering. Possibly username taken. <a href='/register'>Back</a>");
  }
});
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await dbGet(`SELECT * FROM users WHERE username=?`, [username]);
    if (!user) return res.send("Invalid credentials. <a href='/login'>Back</a>");
    if (!checkPassword(user.password_hash, password)) {
      return res.send("Invalid credentials. <a href='/login'>Back</a>");
    }
    req.session.userId = user.id;
    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    res.send("Error logging in. <a href='/login'>Back</a>");
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.get('/dashboard', requireLogin, async (req, res) => {
  try {
    const row = await dbGet(`SELECT * FROM users WHERE id=?`, [req.session.userId]);
    if (!row) return res.redirect('/logout');
    const page = fs.readFileSync(path.join(__dirname, 'views', 'dashboard.html'), 'utf8')
      .replace('{{username}}', row.username)
      .replace('{{sixDigitId}}', row.six_digit_id);
    res.send(page);
  } catch (err) {
    console.error(err);
    res.redirect('/logout');
  }
});
app.get('/encrypt', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'encrypt.html'));
});

app.post('/encrypt', requireLogin, upload.single('file_to_encrypt'), async (req, res) => {
  try {
    if (!req.file) {
      return res.send("No file. <a href='/encrypt'>Back</a>");
    }
    const fileData = fs.readFileSync(req.file.path);

    const userIdsStr = req.body.six_digit_ids || "";
    const thresholdStr = req.body.threshold || "2";
    const userIds = userIdsStr.split(',').map(s => s.trim()).filter(Boolean);
    const threshold = parseInt(thresholdStr, 10);
    if (!userIds.length) {
      return res.send("No user IDs. <a href='/encrypt'>Back</a>");
    }
    if (isNaN(threshold) || threshold < 1) {
      return res.send("Invalid threshold. <a href='/encrypt'>Back</a>");
    }
    const placeholders = userIds.map(() => '?').join(',');
    const rows = await dbAll(`SELECT * FROM users WHERE six_digit_id IN (${placeholders})`, userIds);
    if (rows.length !== userIds.length) {
      return res.send("Some 6-digit IDs not found in DB. <a href='/encrypt'>Back</a>");
    }

    const aesKey = forge.random.getBytesSync(32); 
    const { ciphertext, iv, tag } = aesEncrypt(fileData, Buffer.from(aesKey, 'binary'));
    const aesKeyHex = Buffer.from(aesKey, 'binary').toString('hex');
    const totalUsers = userIds.length;
    const shares = secrets.share(aesKeyHex, totalUsers, threshold);
    const encryptedShares = [];
    for (let i = 0; i < totalUsers; i++) {
      const uid = userIds[i];
      const user = rows.find(r => r.six_digit_id === uid);
      if (!user) {
        return res.send(`User ID ${uid} not found. <a href='/encrypt'>Back</a>`);
      }
      const shareStr = shares[i];  
      const shareBuf = Buffer.from(shareStr, 'utf8');
      const encShareBuf = rsaEncrypt(user.public_key_pem, shareBuf);
      encryptedShares.push({
        six_digit_id: uid,
        encrypted_share: encShareBuf.toString('base64')
      });
    }
    const payload = {
      filename: req.file.originalname,
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      encrypted_shares: encryptedShares,
      threshold
    };
    const outFile = path.join(__dirname, 'uploads', 'encrypted_data.json');
    fs.writeFileSync(outFile, JSON.stringify(payload, null, 2));
    res.setHeader('Content-Disposition', 'attachment; filename="encrypted_data.json"');
    res.setHeader('Content-Type', 'application/json');
    return res.sendFile(outFile);

  } catch (err) {
    console.error(err);
    res.send(`Error encrypting. ${err.message} <a href='/encrypt'>Back</a>`);
  }
});
app.get('/decrypt', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'decrypt.html'));
});

app.post('/decrypt', requireLogin, upload.single('json_file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.send("No JSON file uploaded. <a href='/decrypt'>Back</a>");
    }
    const jsonData = fs.readFileSync(req.file.path, 'utf8');
    let payload;
    try {
      payload = JSON.parse(jsonData);
    } catch(e) {
      return res.send("Invalid JSON. <a href='/decrypt'>Back</a>");
    }
    const user = await dbGet(`SELECT * FROM users WHERE id=?`, [req.session.userId]);
    if (!user) return res.redirect('/logout');
    const myShareObj = payload.encrypted_shares.find(sh => sh.six_digit_id === user.six_digit_id);
    if (!myShareObj) {
      return res.send("You are not authorized for this file (no matching share). <a href='/decrypt'>Back</a>");
    }

    const encShareBuf = Buffer.from(myShareObj.encrypted_share, 'base64');
    let decShareBuf;
    try {
      decShareBuf = rsaDecrypt(user.private_key_pem, encShareBuf);
    } catch (err) {
      return res.send(`Failed to decrypt your share: ${err.message} <a href='/decrypt'>Back</a>`);
    }
    const shareStr = decShareBuf.toString('utf8');
    const fileId = Buffer.from(payload.ciphertext, 'base64').toString('base64').slice(0, 50);
    if (!globalDecryptionPool[fileId]) {
      globalDecryptionPool[fileId] = {};
    }
    globalDecryptionPool[fileId][user.six_digit_id] = shareStr;
    const shares = Object.values(globalDecryptionPool[fileId]);
    if (shares.length >= payload.threshold) {
      const combinedHex = recoverSecret(shares.slice(0, payload.threshold));
      const aesKeyBuf = Buffer.from(combinedHex, 'hex');
      try {
        const ivBuf = Buffer.from(payload.iv, 'base64');
        const tagBuf = Buffer.from(payload.tag, 'base64');
        const ciphertextBuf = Buffer.from(payload.ciphertext, 'base64');
        const plainBuf = aesDecrypt(ciphertextBuf, aesKeyBuf, ivBuf, tagBuf);
        delete globalDecryptionPool[fileId];
        res.setHeader('Content-Disposition', `attachment; filename="DECRYPTED_${payload.filename}"`);
        res.setHeader('Content-Type', 'application/octet-stream');
        return res.send(plainBuf);
      } catch(e) {
        return res.send(`Decrypt error: ${e.message} <a href='/decrypt'>Back</a>`);
      }
    } else {
      return res.send(`Your share is accepted. We have ${shares.length} of ${payload.threshold}. <a href='/decrypt'>Back</a>`);
    }

  } catch (err) {
    console.error(err);
    res.send(`Error in decryption: ${err.message} <a href='/decrypt'>Back</a>`);
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`70% Implementation server running on http://localhost:${PORT}`);
});
