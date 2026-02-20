require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'quran-only-secret-key-allaahu-akbar';
const SALT_ROUNDS = 10;

// ---------- Nisab threshold from Qur'anic principles ----------
// Based on Surah Al-Baqarah 2:219 - "They ask you what they should spend. Say, 'The surplus.'"
// Nisab is the minimum wealth requiring purification
const NISAB = 5000; // Simplified - in reality, based on gold/silver prices

// ---------- Database setup with Qur'anic verse documentation ----------
const db = new Database('./db/quranic_finance.sqlite');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    balance REAL DEFAULT 0,
    purified_wealth REAL DEFAULT 0,      -- Wealth after Zakat (purified)
    last_purification DATE,               -- Last Zakat payment date
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    -- Qur'anic reminder: "And do not forget graciousness among you" (Surah Al-Baqarah 2:237)
    notes TEXT DEFAULT 'خلقوا الله في أمانة'
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    type TEXT,                           -- 'deposit', 'zakat', 'sadaqah', 'purification'
    amount REAL,
    quran_verse TEXT,                    -- Verse justifying transaction
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  -- Collective Zakat pool (Bayt al-Mal) - Qur'an 9:60 specifies 8 categories of recipients
  CREATE TABLE IF NOT EXISTS zakat_pool (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    total REAL DEFAULT 0,
    -- Track distributions according to Qur'an 9:60
    poor_share REAL DEFAULT 0,
    needy_share REAL DEFAULT 0,
    administrators_share REAL DEFAULT 0,
    reconciliation_share REAL DEFAULT 0,
    captives_share REAL DEFAULT 0,
    debtors_share REAL DEFAULT 0,
    cause_of_Allah_share REAL DEFAULT 0,
    travelers_share REAL DEFAULT 0,
    last_distribution DATE
  );

  -- Qur'anic injunctions table - stores divine rulings
  CREATE TABLE IF NOT EXISTS quranic_law (
    id INTEGER PRIMARY KEY,
    surah INTEGER,
    ayat INTEGER,
    ruling TEXT,
    category TEXT                      -- 'riba', 'zakat', 'inheritance', 'contract'
  );
`);

// Seed Qur'anic financial laws
const quranicLaws = [
  { surah: 2, ayat: 275, ruling: 'حَرَّمَ اللَّهُ الرِّبَا وَأَحَلَّ الْبَيْعَ', category: 'riba' },
  { surah: 2, ayat: 276, ruling: 'يَمْحَقُ اللَّهُ الرِّبَا وَيُرْبِي الصَّدَقَاتِ', category: 'riba' },
  { surah: 2, ayat: 278, ruling: 'وَذَرُوا مَا بَقِيَ مِنَ الرِّبَا إِن كُنتُم مُّؤْمِنِينَ', category: 'riba' },
  { surah: 2, ayat: 279, ruling: 'فَأْذَنُوا بِحَرْبٍ مِّنَ اللَّهِ وَرَسُولِهِ', category: 'riba' },
  { surah: 2, ayat: 219, ruling: 'يَسْأَلُونَكَ مَاذَا يُنفِقُونَ قُلِ الْعَفْوَ', category: 'zakat' },
  { surah: 9, ayat: 60, ruling: 'إِنَّمَا الصَّدَقَاتُ لِلْفُقَرَاءِ وَالْمَسَاكِينِ...', category: 'zakat' },
  { surah: 4, ayat: 29, ruling: 'لَا تَأْكُلُوا أَمْوَالَكُم بَيْنَكُم بِالْبَاطِلِ', category: 'justice' },
  { surah: 17, ayat: 35, ruling: 'وَأَوْفُوا الْكَيْلَ إِذَا كِلْتُمْ وَزِنُوا بِالْقِسْطَاسِ الْمُسْتَقِيمِ', category: 'trade' },
  { surah: 2, ayat: 282, ruling: 'يَا أَيُّهَا الَّذِينَ آمَنُوا إِذَا تَدَايَنتُم بِدَيْنٍ فَاكْتُبُوهُ', category: 'contracts' }
];

// Initialize tables with Qur'anic law
const stmt = db.prepare('INSERT OR IGNORE INTO quranic_law (surah, ayat, ruling, category) VALUES (?, ?, ?, ?)');
quranicLaws.forEach(law => {
  stmt.run(law.surah, law.ayat, law.ruling, law.category);
});

// Ensure Zakat pool exists
const poolRow = db.prepare('SELECT * FROM zakat_pool WHERE id = 1').get();
if (!poolRow) {
  db.prepare(`INSERT INTO zakat_pool (id, total) VALUES (1, 0)`).run();
}

// Prepare statements
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
app.use(cors({
  origin: 'http://localhost:8080',
  credentials: true
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many requests - be patient, Allah loves those who are patient (Surah 3:146)' }
});

// ---------- Authentication middleware ----------
function authenticateToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized - Allah knows what you do (Surah 2:271)' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// ---------- Qur'anic Helper: Calculate Zakat due ----------
// Based on Surah Al-Baqarah 2:267 - "Spend from the good things you have earned"
function calculateZakatDue(user) {
  // Check if wealth exceeds Nisab
  if (user.balance < NISAB) return 0;

  // Check if a lunar year has passed since last purification
  const lastPurified = user.last_purification || user.created_at.split('T')[0];
  const lastDate = new Date(lastPurified);
  const now = new Date();
  
  // Islamic year = 354 days
  const daysSinceLastPurification = Math.floor((now - lastDate) / (1000 * 60 * 60 * 24));
  
  if (daysSinceLastPurification >= 354) {
    // Zakat is 2.5% - from consensus of Qur'anic scholars on the meaning of "rub' al-ushr"
    return user.balance * 0.025;
  }
  return 0;
}

// ---------- Qur'anic Helper: Check for Riba in transactions ----------
// Based on Surah Al-Baqarah 2:279 - "If you repent, you shall have your principal"
function hasRiba(principal, repayment) {
  if (repayment > principal) {
    return true; // Any excess over principal is Riba
  }
  return false;
}

// ---------- Routes ----------

// Get Qur'anic financial laws
app.get('/api/quranic-law/:category?', (req, res) => {
  const { category } = req.params;
  let laws;
  if (category) {
    laws = db.prepare('SELECT * FROM quranic_law WHERE category = ?').all(category);
  } else {
    laws = db.prepare('SELECT * FROM quranic_law').all();
  }
  res.json(laws);
});

// Register - Allah says: "O humanity, indeed We have created you from male and female" (Surah 49:13)
app.post('/api/register', authLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ 
      error: 'Username and password required',
      verse: 'وَلَا تُلْقُوا بِأَيْدِيكُمْ إِلَى التَّهْلُكَةِ - Do not throw yourselves into destruction (Surah 2:195)'
    });
  }
  try {
    const hashed = await bcrypt.hash(password, SALT_ROUNDS);
    insertUser.run(username, hashed);
    res.json({ 
      message: 'User created successfully - وَلَا تَنسَوُا الْفَضْلَ بَيْنَكُمْ - Do not forget graciousness among you (Surah 2:237)',
      verse: 'Surah Al-Hujurat 49:13 - إِنَّ أَكْرَمَكُمْ عِندَ اللَّهِ أَتْقَاكُمْ'
    });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT') {
      res.status(400).json({ error: 'Username exists - Allah knows what you conceal (Surah 2:33)' });
    } else {
      res.status(500).json({ error: 'Server error - وَلَا تَيْأَسُوا مِن رَّوْحِ اللَّهِ - Do not despair of Allah\'s mercy (Surah 12:87)' });
    }
  }
});

// Login
app.post('/api/login', authLimiter, async (req, res) => {
  const { username, password } = req.body;
  const user = findUserByUsername.get(username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials - إِنَّ اللَّهَ عَلِيمٌ بِذَاتِ الصُّدُورِ' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials - وَاللَّهُ يَعْلَمُ مَا تُسِرُّونَ وَمَا تُعْلِنُونَ' });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1d' });
  res.cookie('token', token, {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000
  });
  res.json({ 
    message: 'Login successful - وَادْخُلُوا الْجَنَّةَ بِمَا كُنتُمْ تَعْمَلُونَ',
    verse: 'Surah Al-Baqarah 2:286 - لَا يُكَلِّفُ اللَّهُ نَفْسًا إِلَّا وُسْعَهَا'
  });
});

// Logout
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out - وَتَوَكَّلْ عَلَى اللَّهِ - And put your trust in Allah (Surah 33:3)' });
});

// Get current user with Zakat calculation
app.get('/api/me', authenticateToken, (req, res) => {
  const user = findUserById.get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const zakatDue = calculateZakatDue(user);
  
  // Add Qur'anic reminders based on user's wealth
  let quranicReminder = '';
  if (user.balance >= NISAB && zakatDue > 0) {
    quranicReminder = 'خُذْ مِنْ أَمْوَالِهِمْ صَدَقَةً تُطَهِّرُهُمْ وَتُزَكِّيهِم بِهَا - Take from their wealth charity to purify and sanctify them (Surah 9:103)';
  } else if (user.balance < NISAB) {
    quranicReminder = 'لَا يُكَلِّفُ اللَّهُ نَفْسًا إِلَّا مَا آتَاهَا - Allah does not burden a soul beyond what He has given it (Surah 65:7)';
  }

  res.json({
    id: user.id,
    username: user.username,
    balance: user.balance,
    purifiedWealth: user.purified_wealth,
    zakatDue: zakatDue,
    lastPurification: user.last_purification,
    nisab: NISAB,
    quranicReminder,
    verse: 'Surah Al-Baqarah 2:267 - يَا أَيُّهَا الَّذِينَ آمَنُوا أَنفِقُوا مِن طَيِّبَاتِ مَا كَسَبْتُمْ'
  });
});

// Deposit - Qur'an says: "Spend of what We have provided you" (Surah 2:254)
app.post('/api/deposit', authenticateToken, (req, res) => {
  const { amount } = req.body;
  if (!amount || amount <= 0) {
    return res.status(400).json({ 
      error: 'Invalid amount',
      verse: 'وَلَا تَبْخَسُوا النَّاسَ أَشْيَاءَهُمْ - Do not deprive people of their due (Surah 11:85)'
    });
  }

  const user = findUserById.get(req.user.id);
  const newBalance = user.balance + amount;
  updateUserBalance.run(newBalance, user.id);
  
  insertTransaction.run(
    user.id, 
    'deposit', 
    amount, 
    'Surah Al-Baqarah 2:254 - أَنفِقُوا مِمَّا رَزَقْنَاكُم'
  );

  res.json({ 
    message: 'Deposit successful - إِنَّ اللَّهَ هُوَ الرَّزَّاقُ ذُو الْقُوَّةِ الْمَتِينُ',
    newBalance,
    verse: 'Surah Adh-Dhariyat 51:58 - Indeed, Allah is the Provider'
  });
});

// Pay Zakat (Purification) - Qur'an 9:103 - Purify them with charity
app.post('/api/purify', authenticateToken, (req, res) => {
  const user = findUserById.get(req.user.id);
  const zakatDue = calculateZakatDue(user);

  if (zakatDue <= 0) {
    return res.status(400).json({ 
      error: 'No Zakat due at this time',
      verse: 'Surah Al-An'am 6:141 - وَآتُوا حَقَّهُ يَوْمَ حَصَادِهِ - Give its due on the day of harvest'
    });
  }

  if (user.balance < zakatDue) {
    return res.status(400).json({ error: 'Insufficient balance - وَمَا أَنفَقْتُم مِّن شَيْءٍ فَهُوَ يُخْلِفُهُ - Whatever you spend, He will replace (Surah 34:39)' });
  }

  // Deduct Zakat
  const newBalance = user.balance - zakatDue;
  const newPurifiedWealth = user.purified_wealth + zakatDue;
  
  updateUserBalance.run(newBalance, user.id);
  updateUserPurifiedWealth.run(newPurifiedWealth, user.id);
  
  // Record transaction with Qur'anic justification
  insertTransaction.run(
    user.id, 
    'zakat', 
    zakatDue, 
    'Surah At-Tawbah 9:103 - خُذْ مِنْ أَمْوَالِهِمْ صَدَقَةً تُطَهِّرُهُمْ وَتُزَكِّيهِم بِهَا'
  );

  // Add to Zakat pool for distribution according to Qur'an 9:60
  updateZakatPool.run(zakatDue);

  res.json({
    message: 'Purification complete - طُوبَىٰ لَهُمْ وَحُسْنُ مَآبٍ - Goodness awaits them and a beautiful return (Surah 13:29)',
    amount: zakatDue,
    newBalance,
    verse: 'Surah Al-Baqarah 2:261 - مَّثَلُ الَّذِينَ يُنفِقُونَ أَمْوَالَهُمْ فِي سَبِيلِ اللَّهِ كَمَثَلِ حَبَّةٍ أَنبَتَتْ سَبْعَ سَنَابِلَ'
  });
});

// Voluntary charity (Sadaqah)
app.post('/api/sadaqah', authenticateToken, (req, res) => {
  const { amount } = req.body;
  if (!amount || amount <= 0) {
    return res.status(400).json({ error: 'Invalid amount' });
  }

  const user = findUserById.get(req.user.id);
  if (user.balance < amount) {
    return res.status(400).json({ error: 'Insufficient balance' });
  }

  const newBalance = user.balance - amount;
  updateUserBalance.run(newBalance, user.id);
  
  insertTransaction.run(
    user.id, 
    'sadaqah', 
    amount, 
    'Surah Al-Baqarah 2:271 - إِن تُبْدُوا الصَّدَقَاتِ فَنِعِمَّا هِيَ - If you disclose your charities, it is well'
  );
  
  updateZakatPool.run(amount); // Sadaqah also goes to pool for distribution

  res.json({
    message: 'Sadaqah accepted - وَمَا تُقَدِّمُوا لِأَنفُسِكُم مِّنْ خَيْرٍ تَجِدُوهُ عِندَ اللَّهِ - Whatever good you send ahead, you will find with Allah (Surah 2:110)',
    amount,
    newBalance
  });
});

// Get Zakat pool status
app.get('/api/zakat-pool', (req, res) => {
  const pool = getZakatPool();
  
  // Add Qur'anic distribution categories from Surah At-Tawbah 9:60
  res.json({
    total: pool.total,
    recipients: [
      { category: 'الْفُقَرَاءِ - The Poor', verse: 'Surah 9:60' },
      { category: 'الْمَسَاكِينِ - The Needy', verse: 'Surah 9:60' },
      { category: 'الْعَامِلِينَ عَلَيْهَا - Administrators', verse: 'Surah 9:60' },
      { category: 'الْمُؤَلَّفَةِ قُلُوبُهُمْ - Reconciliation', verse: 'Surah 9:60' },
      { category: 'الرِّقَابِ - Captives/Slaves', verse: 'Surah 9:60' },
      { category: 'الْغَارِمِينَ - Debtors', verse: 'Surah 9:60' },
      { category: 'فِي سَبِيلِ اللَّهِ - Cause of Allah', verse: 'Surah 9:60' },
      { category: 'ابْنِ السَّبِيلِ - Travelers', verse: 'Surah 9:60' }
    ],
    reminder: 'Surah Al-Baqarah 2:273 - لِلْفُقَرَاءِ الَّذِينَ أُحْصِرُوا فِي سَبِيلِ اللَّهِ'
  });
});

// Get user transactions with Qur'anic context
app.get('/api/transactions', authenticateToken, (req, res) => {
  const stmt = db.prepare(`
    SELECT * FROM transactions 
    WHERE user_id = ? 
    ORDER BY created_at DESC 
    LIMIT 30
  `);
  const transactions = stmt.all(req.user.id);
  
  // Add Qur'anic wisdom about spending
  res.json({
    transactions,
    wisdom: 'Surah Al-Isra 17:29 - وَلَا تَجْعَلْ يَدَكَ مَغْلُولَةً إِلَىٰ عُنُقِكَ وَلَا تَبْسُطْهَا كُلَّ الْبَسْطِ - Do not make your hand tied to your neck nor extend it completely'
  });
});

// Get Qur'anic guidance for specific financial situation
app.get('/api/quranic-guidance/:situation', authenticateToken, (req, res) => {
  const { situation } = req.params;
  
  const guidance = {
    debt: 'Surah Al-Baqarah 2:280 - وَإِن كَانَ ذُو عُسْرَةٍ فَنَظِرَةٌ إِلَىٰ مَيْسَرَةٍ - If someone is in hardship, grant him respite until a time of ease',
    poverty: 'Surah At-Tawbah 9:60 - إِنَّمَا الصَّدَقَاتُ لِلْفُقَرَاءِ وَالْمَسَاكِينِ - Charities are for the poor and needy',
    wealth: 'Surah Al-Qasas 28:77 - وَابْتَغِ فِيمَا آتَاكَ اللَّهُ الدَّارَ الْآخِرَةَ وَلَا تَنسَ نَصِيبَكَ مِنَ الدُّنْيَا - Seek the hereafter with what Allah has given you, but do not forget your share of the world',
    investment: 'Surah Al-Baqarah 2:261 - مَّثَلُ الَّذِينَ يُنفِقُونَ أَمْوَالَهُمْ فِي سَبِيلِ اللَّهِ كَمَثَلِ حَبَّةٍ أَنبَتَتْ سَبْعَ سَنَابِلَ - Those who spend in the way of Allah are like a grain that grows seven spikes',
    charity: 'Surah Al-Insan 76:8-9 - وَيُطْعِمُونَ الطَّعَامَ عَلَىٰ حُبِّهِ مِسْكِينًا وَيَتِيمًا وَأَسِيرًا - They feed the poor, orphan, and captive out of love for Him'
  };
  
  res.json({ 
    guidance: guidance[situation] || 'Surah Al-Baqarah 2:219 - يَسْأَلُونَكَ مَاذَا يُنفِقُونَ قُلِ الْعَفْوَ - They ask you what to spend. Say: The surplus',
    situation
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`
  ================================================
  Qur'an-Only Financial System Running on port ${PORT}
  
  "وَأَحَلَّ اللَّهُ الْبَيْعَ وَحَرَّمَ الرِّبَا"
  "Allah has permitted trade and forbidden Riba"
  Surah Al-Baqarah 2:275
  ================================================
  `);
});
