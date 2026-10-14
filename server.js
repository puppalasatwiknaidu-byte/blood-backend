require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool, types } = require('pg');

types.setTypeParser(1082, (v) => v); // keep DATE columns as 'YYYY-MM-DD' strings

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // required for Neon
});

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';
const SHELF_LIFE_DAYS = 42;

const GROUPS = ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'];
// recipient group -> donor groups whose red cells are compatible
const COMPAT = {
  'A+': ['A+', 'A-', 'O+', 'O-'],
  'A-': ['A-', 'O-'],
  'B+': ['B+', 'B-', 'O+', 'O-'],
  'B-': ['B-', 'O-'],
  'AB+': ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'],
  'AB-': ['A-', 'B-', 'AB-', 'O-'],
  'O+': ['O+', 'O-'],
  'O-': ['O-'],
};

const SCHEMA = `
CREATE TABLE IF NOT EXISTS donors (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  age INT NOT NULL,
  gender TEXT,
  phone TEXT,
  blood_group TEXT NOT NULL,
  weight NUMERIC NOT NULL,
  hemoglobin NUMERIC NOT NULL,
  last_donation DATE,
  eligible BOOLEAN NOT NULL,
  screening_note TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS blood_units (
  id SERIAL PRIMARY KEY,
  unit_code TEXT UNIQUE NOT NULL,
  donor_id INT REFERENCES donors(id),
  blood_group TEXT NOT NULL,
  test_result TEXT NOT NULL DEFAULT 'Passed',
  collected_on DATE NOT NULL DEFAULT CURRENT_DATE,
  expiry_date DATE NOT NULL,
  status TEXT NOT NULL DEFAULT 'Available'
);
CREATE TABLE IF NOT EXISTS patients (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  age INT NOT NULL,
  gender TEXT,
  phone TEXT,
  blood_group TEXT NOT NULL,
  hospital TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);
ALTER TABLE patients ADD COLUMN IF NOT EXISTS username TEXT UNIQUE;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS password_hash TEXT;
CREATE TABLE IF NOT EXISTS requests (
  id SERIAL PRIMARY KEY,
  patient_name TEXT NOT NULL,
  hospital TEXT NOT NULL,
  blood_group TEXT NOT NULL,
  units_needed INT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending',
  created_at TIMESTAMP DEFAULT NOW()
);
ALTER TABLE requests ADD COLUMN IF NOT EXISTS patient_id INT REFERENCES patients(id);
CREATE TABLE IF NOT EXISTS transactions (
  id SERIAL PRIMARY KEY,
  type TEXT NOT NULL,
  unit_code TEXT,
  request_id INT,
  note TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);
`;

// ---------- helpers ----------
const httpErr = (status, message) => Object.assign(new Error(message), { status });
const wrap = (fn) => (req, res) =>
  fn(req, res).catch((e) => {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Server error' });
  });

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
}
const role = (r) => (req, res, next) =>
  req.user && req.user.role === r ? next() : res.status(403).json({ error: 'Forbidden' });

const hashPw = (pw) => {
  const salt = crypto.randomBytes(16).toString('hex');
  return `${salt}:${crypto.scryptSync(pw, salt, 64).toString('hex')}`;
};
const checkPw = (pw, stored) => {
  const [salt, hash] = (stored || '').split(':');
  if (!salt || !hash) return false;
  return crypto.timingSafeEqual(crypto.scryptSync(pw, salt, 64), Buffer.from(hash, 'hex'));
};
const PATIENT_COLS = 'id, name, age, gender, phone, blood_group, hospital, username, created_at';

// ---------- public routes ----------
app.get('/', (req, res) => res.send('Blood Bank API is running'));

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    return res.json({ token: jwt.sign({ user: username, role: 'admin' }, JWT_SECRET, { expiresIn: '12h' }) });
  }
  res.status(401).json({ error: 'Invalid username or password' });
});

// ---------- patient self-service (public: register + login) ----------
app.post('/api/patient/register', wrap(async (req, res) => {
  const { name, age, gender, phone, blood_group, hospital, username, password } = req.body || {};
  if (!name || !age || !blood_group || !hospital || !username || !password) throw httpErr(400, 'Please fill all required fields');
  if (!GROUPS.includes(blood_group)) throw httpErr(400, 'Invalid blood group');
  const uname = String(username).trim().toLowerCase();
  if (uname.length < 3) throw httpErr(400, 'Username must be at least 3 characters');
  if (String(password).length < 6) throw httpErr(400, 'Password must be at least 6 characters');
  let patient;
  try {
    patient = (await pool.query(
      `INSERT INTO patients (name, age, gender, phone, blood_group, hospital, username, password_hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [name, age, gender || null, phone || null, blood_group, hospital, uname, hashPw(String(password))]
    )).rows[0];
  } catch (e) {
    if (e.code === '23505') throw httpErr(409, 'Username already taken');
    throw e;
  }
  res.status(201).json({ token: jwt.sign({ role: 'patient', id: patient.id }, JWT_SECRET, { expiresIn: '12h' }) });
}));

app.post('/api/patient/login', wrap(async (req, res) => {
  const { username, password } = req.body || {};
  const p = (await pool.query('SELECT id, password_hash FROM patients WHERE username=$1', [String(username || '').trim().toLowerCase()])).rows[0];
  if (!p || !checkPw(String(password || ''), p.password_hash)) throw httpErr(401, 'Invalid username or password');
  res.json({ token: jwt.sign({ role: 'patient', id: p.id }, JWT_SECRET, { expiresIn: '12h' }) });
}));

// everything below needs a token
app.use('/api', auth);

// ---------- patient-only routes ----------
app.get('/api/me', role('patient'), wrap(async (req, res) => {
  const p = (await pool.query(`SELECT ${PATIENT_COLS} FROM patients WHERE id=$1`, [req.user.id])).rows[0];
  if (!p) throw httpErr(404, 'Patient not found');
  res.json(p);
}));

app.get('/api/me/requests', role('patient'), wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM requests WHERE patient_id=$1 ORDER BY id DESC', [req.user.id]);
  res.json(rows);
}));

app.post('/api/me/requests', role('patient'), wrap(async (req, res) => {
  const units = Number(req.body && req.body.units_needed);
  if (!units || units < 1) throw httpErr(400, 'Enter how many units you need');
  const p = (await pool.query('SELECT * FROM patients WHERE id=$1', [req.user.id])).rows[0];
  if (!p) throw httpErr(404, 'Patient not found');
  const { rows } = await pool.query(
    'INSERT INTO requests (patient_id, patient_name, hospital, blood_group, units_needed) VALUES ($1,$2,$3,$4,$5) RETURNING *',
    [p.id, p.name, p.hospital, p.blood_group, units]
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/me', role('patient'), wrap(async (req, res) => {
  const { name, age, gender, phone, blood_group, hospital } = req.body || {};
  if (!name || !age || !blood_group || !hospital) throw httpErr(400, 'Please fill all required fields');
  if (!GROUPS.includes(blood_group)) throw httpErr(400, 'Invalid blood group');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `UPDATE patients SET name=$2, age=$3, gender=$4, phone=$5, blood_group=$6, hospital=$7 WHERE id=$1 RETURNING ${PATIENT_COLS}`,
      [req.user.id, name, age, gender || null, phone || null, blood_group, hospital]
    );
    if (!rows.length) throw httpErr(404, 'Patient not found');
    // keep still-pending requests in sync so the right blood group is issued
    await client.query(
      `UPDATE requests SET patient_name=$2, hospital=$3, blood_group=$4 WHERE patient_id=$1 AND status='Pending'`,
      [req.user.id, name, hospital, blood_group]
    );
    await client.query('COMMIT');
    res.json(rows[0]);
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}));

app.post('/api/me/password', role('patient'), wrap(async (req, res) => {
  const { current_password, new_password } = req.body || {};
  if (!current_password || !new_password) throw httpErr(400, 'Fill both password fields');
  if (String(new_password).length < 6) throw httpErr(400, 'New password must be at least 6 characters');
  const p = (await pool.query('SELECT password_hash FROM patients WHERE id=$1', [req.user.id])).rows[0];
  if (!p || !checkPw(String(current_password), p.password_hash)) throw httpErr(400, 'Current password is incorrect');
  await pool.query('UPDATE patients SET password_hash=$2 WHERE id=$1', [req.user.id, hashPw(String(new_password))]);
  res.json({ ok: true });
}));

app.put('/api/me/requests/:id', role('patient'), wrap(async (req, res) => {
  const units = Number(req.body && req.body.units_needed);
  if (!units || units < 1) throw httpErr(400, 'Enter a valid number of units');
  const { rows } = await pool.query(
    `UPDATE requests SET units_needed=$3 WHERE id=$1 AND patient_id=$2 AND status='Pending' RETURNING *`,
    [req.params.id, req.user.id, units]
  );
  if (!rows.length) throw httpErr(400, 'Only your pending requests can be edited');
  res.json(rows[0]);
}));

app.delete('/api/me/requests/:id', role('patient'), wrap(async (req, res) => {
  const { rowCount } = await pool.query(
    `UPDATE requests SET status='Cancelled' WHERE id=$1 AND patient_id=$2 AND status='Pending'`,
    [req.params.id, req.user.id]
  );
  if (!rowCount) throw httpErr(400, 'Only your pending requests can be cancelled');
  res.json({ ok: true });
}));

// everything below is admin only
app.use('/api', role('admin'));

// ---------- donors (registration + screening) ----------
app.get('/api/donors', wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM donors ORDER BY id DESC');
  res.json(rows);
}));

app.post('/api/donors', wrap(async (req, res) => {
  const { name, age, gender, phone, blood_group, weight, hemoglobin, last_donation } = req.body || {};
  if (!name || !age || !blood_group || !weight || !hemoglobin) throw httpErr(400, 'Please fill all required fields');
  if (!GROUPS.includes(blood_group)) throw httpErr(400, 'Invalid blood group');

  // basic screening rules
  const problems = [];
  if (age < 18 || age > 65) problems.push('Age must be 18-65');
  if (weight < 50) problems.push('Weight must be at least 50 kg');
  if (hemoglobin < 12.5) problems.push('Hemoglobin must be at least 12.5 g/dL');
  if (last_donation) {
    const days = (Date.now() - new Date(last_donation).getTime()) / 86400000;
    if (days < 90) problems.push('Last donation was less than 90 days ago');
  }
  const eligible = problems.length === 0;

  const { rows } = await pool.query(
    `INSERT INTO donors (name, age, gender, phone, blood_group, weight, hemoglobin, last_donation, eligible, screening_note)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
    [name, age, gender || null, phone || null, blood_group, weight, hemoglobin, last_donation || null, eligible,
     eligible ? 'Passed screening' : problems.join('; ')]
  );
  res.status(201).json(rows[0]);
}));

// ---------- blood units (collection + testing + storage) ----------
app.get('/api/units', wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT u.*, d.name AS donor_name FROM blood_units u
     LEFT JOIN donors d ON d.id = u.donor_id ORDER BY u.id DESC`
  );
  res.json(rows);
}));

app.post('/api/units', wrap(async (req, res) => {
  const { donor_id, test_result } = req.body || {};
  if (!donor_id) throw httpErr(400, 'Select a donor');
  const result = test_result === 'Failed' ? 'Failed' : 'Passed';

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const donor = (await client.query('SELECT * FROM donors WHERE id=$1 FOR UPDATE', [donor_id])).rows[0];
    if (!donor) throw httpErr(404, 'Donor not found');
    if (!donor.eligible) throw httpErr(400, 'Donor did not pass screening');

    const code = `BU-${Date.now().toString().slice(-8)}${Math.floor(Math.random() * 90 + 10)}`;
    const status = result === 'Passed' ? 'Available' : 'Discarded';
    const unit = (await client.query(
      `INSERT INTO blood_units (unit_code, donor_id, blood_group, test_result, expiry_date, status)
       VALUES ($1,$2,$3,$4, CURRENT_DATE + $5::int, $6) RETURNING *`,
      [code, donor.id, donor.blood_group, result, SHELF_LIFE_DAYS, status]
    )).rows[0];
    await client.query('UPDATE donors SET last_donation = CURRENT_DATE, eligible = FALSE, screening_note = $2 WHERE id=$1',
      [donor.id, 'Donated today - not eligible for 90 days']);
    await client.query(`INSERT INTO transactions (type, unit_code, note) VALUES ('COLLECTED',$1,$2)`,
      [code, `${donor.blood_group} from ${donor.name}, tests ${result}${result === 'Failed' ? ' (discarded)' : ''}`]);
    await client.query('COMMIT');
    res.status(201).json(unit);
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}));

app.post('/api/units/discard-expired', wrap(async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE blood_units SET status='Discarded' WHERE status='Available' AND expiry_date < CURRENT_DATE RETURNING unit_code`
  );
  for (const u of rows) {
    await pool.query(`INSERT INTO transactions (type, unit_code, note) VALUES ('DISCARDED',$1,'Expired')`, [u.unit_code]);
  }
  res.json({ discarded: rows.length });
}));

// ---------- inventory ----------
app.get('/api/inventory', wrap(async (req, res) => {
  const stock = (await pool.query(
    `SELECT blood_group, COUNT(*)::int AS units FROM blood_units
     WHERE status='Available' AND expiry_date >= CURRENT_DATE GROUP BY blood_group`
  )).rows;
  const expiring = (await pool.query(
    `SELECT unit_code, blood_group, expiry_date FROM blood_units
     WHERE status='Available' AND expiry_date BETWEEN CURRENT_DATE AND CURRENT_DATE + 7 ORDER BY expiry_date`
  )).rows;
  const expired = (await pool.query(
    `SELECT COUNT(*)::int AS n FROM blood_units WHERE status='Available' AND expiry_date < CURRENT_DATE`
  )).rows[0].n;
  res.json({ groups: GROUPS.map((g) => ({ blood_group: g, units: (stock.find((s) => s.blood_group === g) || {}).units || 0 })), expiring, expired });
}));

// ---------- patients ----------
app.get('/api/patients', wrap(async (req, res) => {
  const { rows } = await pool.query(`SELECT ${PATIENT_COLS} FROM patients ORDER BY id DESC`);
  res.json(rows);
}));

app.post('/api/patients', wrap(async (req, res) => {
  const { name, age, gender, phone, blood_group, hospital } = req.body || {};
  if (!name || !age || !blood_group || !hospital) throw httpErr(400, 'Please fill all required fields');
  if (!GROUPS.includes(blood_group)) throw httpErr(400, 'Invalid blood group');
  const { rows } = await pool.query(
    'INSERT INTO patients (name, age, gender, phone, blood_group, hospital) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, name, blood_group, hospital',
    [name, age, gender || null, phone || null, blood_group, hospital]
  );
  res.status(201).json(rows[0]);
}));

// ---------- blood requests + issue ----------
app.get('/api/requests', wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM requests ORDER BY id DESC');
  res.json(rows);
}));

app.post('/api/requests', wrap(async (req, res) => {
  const { patient_id, units_needed } = req.body || {};
  if (!patient_id || !units_needed) throw httpErr(400, 'Select a patient and enter units needed');
  if (Number(units_needed) < 1) throw httpErr(400, 'Units must be at least 1');
  const patient = (await pool.query('SELECT * FROM patients WHERE id=$1', [patient_id])).rows[0];
  if (!patient) throw httpErr(404, 'Patient not found');
  const { rows } = await pool.query(
    'INSERT INTO requests (patient_id, patient_name, hospital, blood_group, units_needed) VALUES ($1,$2,$3,$4,$5) RETURNING *',
    [patient.id, patient.name, patient.hospital, patient.blood_group, units_needed]
  );
  res.status(201).json(rows[0]);
}));

app.post('/api/requests/:id/issue', wrap(async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const r = (await client.query('SELECT * FROM requests WHERE id=$1 FOR UPDATE', [req.params.id])).rows[0];
    if (!r) throw httpErr(404, 'Request not found');
    if (r.status !== 'Pending') throw httpErr(400, `Request is already ${r.status}`);

    // compatibility match: exact group first, then oldest expiry first (FEFO)
    const units = (await client.query(
      `SELECT * FROM blood_units
       WHERE status='Available' AND test_result='Passed' AND expiry_date >= CURRENT_DATE AND blood_group = ANY($1)
       ORDER BY (blood_group = $2) DESC, expiry_date ASC LIMIT $3 FOR UPDATE`,
      [COMPAT[r.blood_group], r.blood_group, r.units_needed]
    )).rows;
    if (units.length < r.units_needed) {
      throw httpErr(400, `Only ${units.length} compatible unit(s) available, ${r.units_needed} needed`);
    }
    for (const u of units) {
      await client.query(`UPDATE blood_units SET status='Issued' WHERE id=$1`, [u.id]);
      await client.query(`INSERT INTO transactions (type, unit_code, request_id, note) VALUES ('ISSUED',$1,$2,$3)`,
        [u.unit_code, r.id, `${u.blood_group} issued to ${r.patient_name} (${r.hospital})`]);
    }
    await client.query(`UPDATE requests SET status='Issued' WHERE id=$1`, [r.id]);
    await client.query('COMMIT');
    res.json({ issued: units.map((u) => u.unit_code) });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}));

app.post('/api/requests/:id/reject', wrap(async (req, res) => {
  const { rowCount } = await pool.query(`UPDATE requests SET status='Rejected' WHERE id=$1 AND status='Pending'`, [req.params.id]);
  if (!rowCount) throw httpErr(400, 'Request not found or not pending');
  res.json({ ok: true });
}));

// ---------- transactions / report ----------
app.get('/api/transactions', wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM transactions ORDER BY id DESC LIMIT 200');
  res.json(rows);
}));

// ---------- start ----------
const PORT = process.env.PORT || 5000;
pool.query(SCHEMA)
  .then(() => app.listen(PORT, () => console.log(`API running on port ${PORT}`)))
  .catch((e) => {
    console.error('Database connection failed:', e.message);
    process.exit(1);
  });
