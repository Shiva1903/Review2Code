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
const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, 'public')));

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({
  secret: 'sessionSecret',
  resave: false,
  saveUninitialized: true
}));

const upload = multer({ dest: uploadsDir });

const db = new sqlite3.Database('secure_file.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        public_key_pem TEXT,
        private_key_pem TEXT
      )`);
  db.run(`CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uploader_id INTEGER,
        original_filename TEXT,
        json_payload TEXT,
        recipients TEXT,
        threshold INTEGER,
        file_id TEXT
      )`);
});

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve(this.lastID);
    });
  });
}
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

function generateRSAKeyPair(bits = 2048) {
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
  const iv = forge.random.getBytesSync(12);
  const cipher = forge.cipher.createCipher('AES-GCM', keyBuf.toString('binary'));
  cipher.start({ iv: iv });
  cipher.update(forge.util.createBuffer(dataBuf));
  cipher.finish();
  const ciphertext = cipher.output.getBytes();
  const tag = cipher.mode.tag.getBytes();
  return {
    ciphertext: Buffer.from(ciphertext, 'binary'),
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
    return res.redirect('/login.html');
  }
  next();
}

const globalDecryptionPool = {};

function serveTemplate(res, templatePath, replacements) {
  fs.readFile(templatePath, 'utf8', (err, data) => {
    if (err) return res.status(500).send("Error loading template.");
    let output = data;
    for (let key in replacements) {
      const token = new RegExp(`{{\\s*${key}\\s*}}`, 'g');
      output = output.replace(token, replacements[key]);
    }
    res.send(output);
  });
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'home.html'));
});
app.get('/home.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'home.html'));
});

app.get('/register.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'register.html'));
});
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.sendFile(path.join(__dirname, 'views', 'register.html'));
    }
    const { privateKeyPem, publicKeyPem } = await generateRSAKeyPair();
    const passHash = hashPassword(password);
    await dbRun(
      `INSERT INTO users (username, password_hash, public_key_pem, private_key_pem)
       VALUES (?, ?, ?, ?)`,
      [username, passHash, publicKeyPem, privateKeyPem]
    );
    res.redirect('/login.html');
  } catch (err) {
    console.error(err);
    res.sendFile(path.join(__dirname, 'views', 'register.html'));
  }
});

app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await dbGet(`SELECT * FROM users WHERE username=?`, [username]);
    if (!user || !checkPassword(user.password_hash, password)) {
      return res.sendFile(path.join(__dirname, 'views', 'login.html'));
    }
    req.session.userId = user.id;
    res.redirect('/dashboard.html');
  } catch (err) {
    console.error(err);
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/home.html');
  });
});

app.get('/dashboard.html', requireLogin, async (req, res) => {
  try {
    const user = await dbGet(`SELECT * FROM users WHERE id=?`, [req.session.userId]);
    if (!user) return res.redirect('/logout');
    const files = await dbAll(`SELECT * FROM files`);
    let fileListHtml = "";
    files.filter(f => {
      const recips = JSON.parse(f.recipients);
      return recips.includes(user.username);
    }).forEach(f => {
      fileListHtml += `<div class="file-item">
                <h4>${f.original_filename}</h4>
                <a href="/decrypt/${f.file_id}" class="btn">Decrypt</a>
            </div>`;
    });
    serveTemplate(res, path.join(__dirname, 'views', 'dashboard.html'), {
      username: user.username,
      fileList: fileListHtml || "<p>No files available.</p>"
    });
  } catch (err) {
    console.error(err);
    res.redirect('/logout');
  }
});

app.get('/encrypt.html', requireLogin, async (req, res) => {
  try {
    const users = await dbAll(`SELECT * FROM users WHERE id != ?`, [req.session.userId]);
    let userOptions = "";
    users.forEach(u => {
      userOptions += `<div class="checkbox-group">
                <input type="checkbox" name="recipients" value="${u.username}" id="user-${u.id}" />
                <label for="user-${u.id}">${u.username}</label>
            </div>`;
    });
    serveTemplate(res, path.join(__dirname, 'views', 'encrypt.html'), {
      userOptions: userOptions
    });
  } catch (err) {
    console.error(err);
    res.redirect('/dashboard.html');
  }
});

app.post('/encrypt', requireLogin, upload.single('file_to_encrypt'), async (req, res) => {
  try {
    if (!req.file) {
      return res.send("No file uploaded. <a href='/encrypt.html'>Back</a>");
    }
    let recipients = req.body.recipients;
    if (!recipients) {
      return res.send("No recipients selected. <a href='/encrypt.html'>Back</a>");
    }
    if (!Array.isArray(recipients)) {
      recipients = [recipients];
    }
    const threshold = parseInt(req.body.threshold, 10);
    if (isNaN(threshold) || threshold < 1 || threshold > recipients.length) {
      return res.send("Invalid threshold. <a href='/encrypt.html'>Back</a>");
    }
    const fileData = fs.readFileSync(req.file.path);
    const originalFileSize = req.file.size;
    const aesKey = forge.random.getBytesSync(32);
    const aesKeyBuf = Buffer.from(aesKey, 'binary');
    const { ciphertext, iv, tag } = aesEncrypt(fileData, aesKeyBuf);
    const aesKeyHex = aesKeyBuf.toString('hex');
    const shares = splitSecret(aesKeyHex, recipients.length, threshold);
    let encryptedShares = [];
    for (let i = 0; i < recipients.length; i++) {
      const recipUsername = recipients[i];
      const user = await dbGet(`SELECT * FROM users WHERE username=?`, [recipUsername]);
      if (!user) {
        return res.send(`User ${recipUsername} not found. <a href='/encrypt.html'>Back</a>`);
      }
      const shareStr = shares[i];
      const shareBuf = Buffer.from(shareStr, 'utf8');
      const encShareBuf = rsaEncrypt(user.public_key_pem, shareBuf);
      encryptedShares.push({
        username: recipUsername,
        encrypted_share: encShareBuf.toString('base64')
      });
    }
    const file_id = Date.now().toString() + Math.floor(Math.random() * 1000).toString();
    const payload = {
      original_filename: req.file.originalname,
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      encrypted_shares: encryptedShares,
      threshold: threshold,
      file_id: file_id
    };
    const payloadStr = JSON.stringify(payload, null, 2);
    const payloadSize = Buffer.byteLength(payloadStr, 'utf8');
    const overheadRatio = (((payloadSize - originalFileSize) / originalFileSize) * 100).toFixed(2);
    console.log(`Original file size: ${originalFileSize} bytes`);
    console.log(`Payload size: ${payloadSize} bytes`);
    console.log(`Overhead ratio: ${overheadRatio}%`);
    await dbRun(
      `INSERT INTO files (uploader_id, original_filename, json_payload, recipients, threshold, file_id)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [req.session.userId, req.file.originalname, payloadStr, JSON.stringify(recipients), threshold, file_id]
    );
    serveTemplate(res, path.join(__dirname, 'views', 'encryptSuccess.html'), {
      file_id: file_id
    });
  } catch (err) {
    console.error(err);
    res.send(`Error during encryption: ${err.message} <a href='/encrypt.html'>Back</a>`);
  }
});

app.get('/decrypt.html', requireLogin, async (req, res) => {
  try {
    const user = await dbGet(`SELECT * FROM users WHERE id=?`, [req.session.userId]);
    if (!user) return res.redirect('/logout');
    const files = await dbAll(`SELECT * FROM files`);
    let fileListHtml = "";
    files.filter(f => {
      const recips = JSON.parse(f.recipients);
      return recips.includes(user.username);
    }).forEach(f => {
      fileListHtml += `<div class="file-item">
          <h4>${f.original_filename}</h4>
          <a href="/decrypt/${f.file_id}" class="btn">Decrypt</a>
      </div>`;
    });
    serveTemplate(res, path.join(__dirname, 'views', 'decrypt.html'), {
      fileList: fileListHtml || "<p>No files available for decryption.</p>"
    });
  } catch (err) {
    console.error(err);
    res.redirect('/dashboard.html');
  }
});

app.get('/decrypt/:file_id', requireLogin, async (req, res) => {
  try {
    const file_id = req.params.file_id;
    const fileRecord = await dbGet(`SELECT * FROM files WHERE file_id=?`, [file_id]);
    if (!fileRecord) return res.send("File not found or already decrypted. <a href='/decrypt.html'>Back</a>");
    const payload = JSON.parse(fileRecord.json_payload);
    const user = await dbGet(`SELECT * FROM users WHERE id=?`, [req.session.userId]);
    if (!user) return res.redirect('/logout');
    const myShareObj = payload.encrypted_shares.find(sh => sh.username === user.username);
    if (!myShareObj) {
      return res.send("You are not authorized for this file. <a href='/decrypt.html'>Back</a>");
    }
    const encShareBuf = Buffer.from(myShareObj.encrypted_share, 'base64');
    let decShareBuf;
    try {
      decShareBuf = rsaDecrypt(user.private_key_pem, encShareBuf);
    } catch (err) {
      return res.send(`Failed to decrypt your share: ${err.message} <a href='/decrypt.html'>Back</a>`);
    }
    const shareStr = decShareBuf.toString('utf8');
    if (!globalDecryptionPool[file_id]) {
      globalDecryptionPool[file_id] = {};
    }
    globalDecryptionPool[file_id][user.username] = shareStr;
    const shares = Object.values(globalDecryptionPool[file_id]);
    if (shares.length >= payload.threshold) {
      const combinedHex = recoverSecret(shares.slice(0, payload.threshold));
      const aesKeyBuf = Buffer.from(combinedHex, 'hex');
      try {
        const ivBuf = Buffer.from(payload.iv, 'base64');
        const tagBuf = Buffer.from(payload.tag, 'base64');
        const ciphertextBuf = Buffer.from(payload.ciphertext, 'base64');
        const plainBuf = aesDecrypt(ciphertextBuf, aesKeyBuf, ivBuf, tagBuf);
        delete globalDecryptionPool[file_id];
        await dbRun(`DELETE FROM files WHERE file_id=?`, [file_id]);
        res.setHeader('Content-Disposition', `attachment; filename="DECRYPTED_${payload.original_filename}"`);
        res.setHeader('Content-Type', 'application/octet-stream');
        return res.send(plainBuf);
      } catch (e) {
        return res.send(`Decrypt error: ${e.message} <a href='/decrypt.html'>Back</a>`);
      }
    } else {
      return res.send(`Your share is accepted. We have ${shares.length} of ${payload.threshold} required shares. (Ask other authorized users to click "Decrypt" on this file.) <a href='/decrypt.html'>Back</a>`);
    }
  } catch (err) {
    console.error(err);
    res.send(`Error in decryption: ${err.message} <a href='/decrypt.html'>Back</a>`);
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
