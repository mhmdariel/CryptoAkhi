require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const MetalCardPrinter = require('./metalCardPrinter');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'quran-only-secret-key-allaahu-akbar';
const SALT_ROUNDS = 10;
const NISAB = 5000; // Minimum wealth for Zakat

// ---------- Database setup ----------
const db = new Database('./db/quranic_finance.sqlite');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    balance REAL DEFAULT 0,
    purified_wealth REAL DEFAULT 0,
    last_purification DATE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    type TEXT,
    amount REAL,
    quran_verse TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS zakat_pool (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    total REAL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS debit_cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    card_number TEXT UNIQUE NOT NULL,
    card_hash TEXT NOT NULL,
    pin_hash TEXT NOT NULL,
    expiry_month INTEGER,
    expiry_year INTEGER,
    cvv_hash TEXT,
    status TEXT DEFAULT 'active',
    material TEXT DEFAULT 'plastic',
    issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used DATETIME,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS physical_metal_cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id INTEGER NOT NULL,
    serial_number TEXT UNIQUE NOT NULL,
    chip_id TEXT UNIQUE NOT NULL,
    material TEXT DEFAULT 'stainless_steel_316L',
    manufactured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'active',
    last_used DATETIME,
    FOREIGN KEY(card_id) REFERENCES debit_cards(id)
  );

  CREATE TABLE IF NOT EXISTS card_print_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT UNIQUE NOT NULL,
    card_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    status TEXT,
    error TEXT,
    queued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    started_at DATETIME,
    completed_at DATETIME,
    FOREIGN KEY(card_id) REFERENCES debit_cards(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS printer_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT,
    message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS linked_bank_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    plaid_access_token TEXT,
    plaid_item_id TEXT,
    account_id TEXT,
    account_name TEXT,
    account_type TEXT,
    account_mask TEXT,
    balance_current REAL DEFAULT 0,
    last_sync DATETIME,
    status TEXT DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS external_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    account_id TEXT NOT NULL,
    plaid_transaction_id TEXT UNIQUE,
    amount REAL NOT NULL,
    category TEXT,
    date DATE,
    name TEXT,
    pending BOOLEAN,
    is_interest BOOLEAN DEFAULT 0,
    purified BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS riba_purification (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    source TEXT,
    transaction_id INTEGER,
    purified BOOLEAN DEFAULT 0,
    purified_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS atm_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    card_id INTEGER NOT NULL,
    type TEXT,
    amount REAL,
    atm_id TEXT,
    status TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(card_id) REFERENCES debit_cards(id)
  );
`);

// Ensure Zakat pool exists
if (!db.prepare('SELECT * FROM zakat_pool WHERE id = 1').get()) {
  db.prepare('INSERT INTO zakat_pool (id, total) VALUES (1, 0)').run();
}

// Prepare common statements
const insertUser = db.prepare('INSERT INTO users (username, password, last_purification) VALUES (?, ?, date())');
const findUserByUsername = db.prepare('SELECT * FROM users WHERE username = ?');
const findUserById = db.prepare('SELECT * FROM users WHERE id = ?');
const updateUserBalance = db.prepare('UPDATE users SET balance = ? WHERE id = ?');
const updateUserPurifiedWealth = db.prepare('UPDATE users SET purified_wealth = ?, last_purification = date() WHERE id = ?');
const insertTransaction = db.prepare('INSERT INTO transactions (user_id, type, amount, quran_verse) VALUES (?, ?, ?, ?)');
const getZakatPool = db.prepare('SELECT total FROM zakat_pool WHERE id = 1').get;
const updateZakatPool = db.prepare('UPDATE zakat_pool SET total = total + ? WHERE id = 1');

// ---------- Middleware ----------
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: 'http://localhost:8080', credentials: true }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many requests – Allah loves patience' }
});

function authenticateToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// ---------- Helper functions ----------
function calculateZakatDue(user) {
  if (user.balance < NISAB) return 0;
  const last = user.last_purification || user.created_at.split('T')[0];
  const days = Math.floor((new Date() - new Date(last)) / (1000*60*60*24));
  return days >= 354 ? user.balance * 0.025 : 0;
}

async function hashCardNumber(cardNumber) { return await bcrypt.hash(cardNumber, 10); }
async function hashPIN(pin) { return await bcrypt.hash(pin.toString(), 10); }
async function verifyPIN(plain, hashed) { return await bcrypt.compare(plain.toString(), hashed); }
function generateCardNumber() { return Array(16).fill(0).map(() => Math.floor(Math.random()*10)).join(''); }

// ---------- Printer initialization ----------
let printer = null;
async function initPrinter() {
  printer = new MetalCardPrinter({ port: '/dev/ttyUSB0' });
  try {
    await printer.connect();
    console.log('✅ Metal printer connected');
    printer.on('jobStarted', (job) => {
      db.prepare('UPDATE card_print_jobs SET status = ?, started_at = ? WHERE job_id = ?')
        .run('printing', job.startedAt, job.id);
      db.prepare('INSERT INTO printer_events (event_type, message) VALUES (?, ?)')
        .run('job_started', `Job ${job.id} started`);
    });
    printer.on('jobCompleted', (job) => {
      db.prepare('UPDATE card_print_jobs SET status = ?, completed_at = ? WHERE job_id = ?')
        .run('completed', job.completedAt, job.id);
      db.prepare('INSERT INTO printer_events (event_type, message) VALUES (?, ?)')
        .run('job_completed', `Job ${job.id} completed`);
    });
    printer.on('jobFailed', (job) => {
      db.prepare('UPDATE card_print_jobs SET status = ?, error = ? WHERE job_id = ?')
        .run('failed', job.error, job.id);
      db.prepare('INSERT INTO printer_events (event_type, message) VALUES (?, ?)')
        .run('job_failed', `Job ${job.id} failed: ${job.error}`);
    });
  } catch (err) {
    console.error('❌ Printer connection failed:', err);
  }
}
setTimeout(initPrinter, 2000);

// ---------- Auth routes ----------
app.post('/api/register', authLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const hashed = await bcrypt.hash(password, SALT_ROUNDS);
    insertUser.run(username, hashed);
    res.json({ message: 'User created' });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT') res.status(400).json({ error: 'Username exists' });
    else res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  const { username, password } = req.body;
  const user = findUserByUsername.get(username);
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '1d' });
  res.cookie('token', token, { httpOnly: true, sameSite: 'strict', maxAge: 24*60*60*1000 });
  res.json({ message: 'Login successful' });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out' });
});

app.get('/api/me', authenticateToken, (req, res) => {
  const user = findUserById.get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const zakatDue = calculateZakatDue(user);
  res.json({
    id: user.id,
    username: user.username,
    balance: user.balance,
    purifiedWealth: user.purified_wealth,
    zakatDue,
    lastPurification: user.last_purification,
    nisab: NISAB
  });
});

// ---------- Zakat & Purification ----------
app.post('/api/purify', authenticateToken, (req, res) => {
  const user = findUserById.get(req.user.id);
  const zakatDue = calculateZakatDue(user);
  if (zakatDue <= 0) return res.status(400).json({ error: 'No Zakat due' });
  if (user.balance < zakatDue) return res.status(400).json({ error: 'Insufficient balance' });

  const newBalance = user.balance - zakatDue;
  const newPurified = user.purified_wealth + zakatDue;
  updateUserBalance.run(newBalance, user.id);
  updateUserPurifiedWealth.run(newPurified, user.id);
  insertTransaction.run(user.id, 'zakat', zakatDue, 'Surah At-Tawbah 9:103');
  updateZakatPool.run(zakatDue);

  res.json({ message: 'Purification complete', amount: zakatDue, newBalance });
});

app.post('/api/sadaqah', authenticateToken, (req, res) => {
  const { amount } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });
  const user = findUserById.get(req.user.id);
  if (user.balance < amount) return res.status(400).json({ error: 'Insufficient balance' });
  const newBalance = user.balance - amount;
  updateUserBalance.run(newBalance, user.id);
  insertTransaction.run(user.id, 'sadaqah', amount, 'Surah Al-Baqarah 2:271');
  updateZakatPool.run(amount);
  res.json({ message: 'Sadaqah accepted', amount, newBalance });
});

app.get('/api/zakat-pool', (req, res) => {
  const pool = getZakatPool();
  res.json({ total: pool.total });
});

// ---------- Card issuance ----------
app.post('/api/card/issue', authenticateToken, async (req, res) => {
  const { pin, material = 'plastic' } = req.body;
  if (!pin || pin.length !== 4 || isNaN(pin))
    return res.status(400).json({ error: 'PIN must be 4 digits' });

  const existing = db.prepare('SELECT id FROM debit_cards WHERE user_id = ? AND status = "active"').get(req.user.id);
  if (existing) return res.status(400).json({ error: 'User already has an active card' });

  const cardNumber = generateCardNumber();
  const cardHash = await hashCardNumber(cardNumber);
  const pinHash = await hashPIN(pin);
  const expiryMonth = new Date().getMonth() + 1;
  const expiryYear = new Date().getFullYear() + 5;
  const cvv = Math.floor(100 + Math.random() * 900);
  const cvvHash = await bcrypt.hash(cvv.toString(), 10);
  const last4 = cardNumber.slice(-4);

  const insertCard = db.prepare(`
    INSERT INTO debit_cards (user_id, card_number, card_hash, pin_hash, expiry_month, expiry_year, cvv_hash, material)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const info = insertCard.run(req.user.id, last4, cardHash, pinHash, expiryMonth, expiryYear, cvvHash, material);
  const cardId = info.lastInsertRowid;

  let physicalCardInfo = null;
  if (material === 'metal' && printer) {
    const chipId = crypto.randomBytes(8).toString('hex').toUpperCase();
    const jobId = printer.queueJob({
      cardData: {
        cardNumber,
        expiryMonth,
        expiryYear,
        cvv,
        holderName: req.user.username,
        material: 'stainless_steel_316L',
        chipId
      },
      userId: req.user.id
    });
    db.prepare('INSERT INTO card_print_jobs (job_id, card_id, user_id, status) VALUES (?, ?, ?, "queued")')
      .run(jobId, cardId, req.user.id);
    db.prepare('INSERT INTO physical_metal_cards (card_id, serial_number, chip_id) VALUES (?, ?, ?)')
      .run(cardId, `MC-${new Date().toISOString().slice(2,10).replace(/-/g,'')}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`, chipId);
    physicalCardInfo = { jobId, status: 'queued' };
  }

  res.json({
    message: material === 'metal' ? 'Metal card queued for printing' : 'Plastic card issued',
    last4,
    expiry: `${expiryMonth}/${expiryYear}`,
    material,
    physicalCard: physicalCardInfo
  });
});

app.get('/api/card', authenticateToken, (req, res) => {
  const card = db.prepare('SELECT card_number, expiry_month, expiry_year, status, material, issued_at FROM debit_cards WHERE user_id = ? AND status = "active"').get(req.user.id);
  if (!card) return res.status(404).json({ error: 'No active card' });
  res.json({
    last4: card.card_number,
    expiry: `${card.expiry_month}/${card.expiry_year}`,
    status: card.status,
    material: card.material,
    issuedAt: card.issued_at
  });
});

app.post('/api/card/block', authenticateToken, (req, res) => {
  const result = db.prepare('UPDATE debit_cards SET status = "blocked" WHERE user_id = ? AND status = "active"').run(req.user.id);
  if (result.changes === 0) return res.status(404).json({ error: 'No active card' });
  res.json({ message: 'Card blocked' });
});

app.get('/api/card/physical', authenticateToken, (req, res) => {
  const card = db.prepare('SELECT id FROM debit_cards WHERE user_id = ? AND status = "active"').get(req.user.id);
  if (!card) return res.status(404).json({ error: 'No active card' });
  const physical = db.prepare('SELECT serial_number, chip_id, material, manufactured_at, status FROM physical_metal_cards WHERE card_id = ?').get(card.id);
  if (!physical) return res.json({ message: 'No metal card issued' });
  res.json(physical);
});

// ---------- ATM simulation ----------
app.post('/api/atm/withdraw', async (req, res) => {
  const { cardNumber, pin, amount, chipId } = req.body;
  if (!cardNumber || !pin || !amount || amount <= 0) return res.status(400).json({ error: 'Invalid request' });

  const cards = db.prepare('SELECT * FROM debit_cards WHERE status = "active"').all();
  let foundCard = null;
  for (const card of cards) {
    if (await bcrypt.compare(cardNumber, card.card_hash)) { foundCard = card; break; }
  }
  if (!foundCard) return res.status(404).json({ error: 'Card not found' });

  const pinValid = await verifyPIN(pin, foundCard.pin_hash);
  if (!pinValid) return res.status(401).json({ error: 'Invalid PIN' });

  const now = new Date();
  if (foundCard.expiry_year < now.getFullYear() || (foundCard.expiry_year === now.getFullYear() && foundCard.expiry_month < now.getMonth()+1))
    return res.status(400).json({ error: 'Card expired' });

  // Optional chip verification
  if (chipId && foundCard.material === 'metal') {
    const physical = db.prepare('SELECT chip_id FROM physical_metal_cards WHERE card_id = ?').get(foundCard.id);
    if (!physical || physical.chip_id !== chipId)
      return res.status(403).json({ error: 'Chip authentication failed' });
  }

  const user = findUserById.get(foundCard.user_id);
  if (user.balance < amount) return res.status(400).json({ error: 'Insufficient funds' });

  const newBalance = user.balance - amount;
  updateUserBalance.run(newBalance, foundCard.user_id);
  db.prepare('INSERT INTO atm_transactions (user_id, card_id, type, amount, atm_id, status) VALUES (?, ?, "withdrawal", ?, "ATM001", "completed")')
    .run(foundCard.user_id, foundCard.id, amount);
  db.prepare('UPDATE debit_cards SET last_used = CURRENT_TIMESTAMP WHERE id = ?').run(foundCard.id);

  res.json({ message: 'Withdrawal successful', amount, newBalance });
});

app.post('/api/atm/deposit', async (req, res) => {
  const { cardNumber, pin, amount } = req.body;
  // Similar to withdraw but adding to balance...
  // (Implementation omitted for brevity – similar to withdrawal with balance addition)
});

app.post('/api/atm/balance', async (req, res) => {
  const { cardNumber, pin } = req.body;
  // Find card, verify PIN, return balance
});

// ---------- Printer status endpoints ----------
app.get('/api/printer/status', authenticateToken, (req, res) => {
  if (!printer) return res.status(503).json({ error: 'Printer not connected' });
  res.json(printer.getStatus());
});

app.get('/api/printer/jobs', authenticateToken, (req, res) => {
  const jobs = db.prepare('SELECT * FROM card_print_jobs WHERE user_id = ? ORDER BY queued_at DESC LIMIT 10').all(req.user.id);
  res.json(jobs);
});

// ---------- Bank account linking (Plaid simulation) ----------
app.post('/api/plaid/create_link_token', authenticateToken, (req, res) => {
  res.json({ link_token: 'plaid_sandbox_link_token' }); // mock
});

app.post('/api/plaid/exchange_public_token', authenticateToken, (req, res) => {
  // mock – store a dummy account
  const stmt = db.prepare(`
    INSERT INTO linked_bank_accounts (user_id, plaid_access_token, account_id, account_name, balance_current, last_sync)
    VALUES (?, 'mock_token', 'mock_account', 'Mock Bank Account', 1000, CURRENT_TIMESTAMP)
  `);
  stmt.run(req.user.id);
  res.json({ success: true });
});

app.get('/api/plaid/accounts', authenticateToken, (req, res) => {
  const accounts = db.prepare('SELECT * FROM linked_bank_accounts WHERE user_id = ?').all(req.user.id);
  res.json(accounts);
});

// ---------- Start server ----------
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
