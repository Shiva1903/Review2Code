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

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
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

function generateSixDigitID() {
  return String(Math.floor(100000 + Math.random() * 900000));
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
  cipher.start({ iv });
  cipher.update(forge.util.createBuffer(dataBuf));
  cipher.finish();
  return {
    ciphertext: Buffer.from(cipher.output.getBytes(), 'binary'),
    iv: Buffer.from(iv, 'binary'),
    tag: Buffer.from(cipher.mode.tag.getBytes(), 'binary')
  };
}

function aesDecrypt(ciphertextBuf, keyBuf, ivBuf, tagBuf) {
  const decipher = forge.cipher.createDecipher('AES-GCM', keyBuf.toString('binary'));
  decipher.start({
    iv: ivBuf.toString('binary'),
    tag: forge.util.createBuffer(tagBuf.toString('binary'))
  });
  decipher.update(forge.util.createBuffer(ciphertextBuf));
  if (!decipher.finish()) throw new Error("AES-GCM authentication failed");
  return Buffer.from(decipher.output.getBytes(), 'binary');
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
    if (!username || !password) return res.send("Username & password required. <a href='/register'>Back</a>");
    const sixDigit = generateSixDigitID();
    const { privateKeyPem, publicKeyPem } = await generateRSAKeyPair();
    const passHash = hashPassword(password);
    await dbRun(`
      INSERT INTO users (six_digit_id, username, password_hash, public_key_pem, private_key_pem)
      VALUES (?, ?, ?, ?, ?)
    `, [sixDigit, username, passHash, publicKeyPem, privateKeyPem]);
    res.send(`<h2>Registration Successful</h2><p>Your 6-digit ID: <b>${sixDigit}</b></p><p><a href="/login">Login</a></p>`);
  } catch (err) {
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
    if (!user || !checkPassword(user.password_hash, password)) {
      return res.send("Invalid credentials. <a href='/login'>Back</a>");
    }
    req.session.userId = user.id;
    res.redirect('/dashboard');
  } catch {
    res.send("Error logging in. <a href='/login'>Back</a>");
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.get('/dashboard', requireLogin, async (req, res) => {
  const row = await dbGet(`SELECT * FROM users WHERE id=?`, [req.session.userId]);
  if (!row) return res.redirect('/logout');
  res.send(fs.readFileSync(path.join(__dirname, 'views', 'dashboard.html'), 'utf8')
    .replace('{{username}}', row.username)
    .replace('{{sixDigitId}}', row.six_digit_id));
});

app.get('/encrypt', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'encrypt.html'));
});

app.get('/decrypt', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'decrypt.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
