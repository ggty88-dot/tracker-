const crypto = require('node:crypto');
const { promisify } = require('node:util');
const scrypt = promisify(crypto.scrypt);

const URL_ = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;

const APPS = ['IDOLCHAMP', 'LINC / TIN', 'MUBEAT', 'COOGOONG', 'HIGHER', 'MUNIVERSE'];
const SPECIAL = '10694';
const HASH = 'votes';
const SEQ = 'votes:seq';

/* ---------- accounts / PIN settings ---------- */
const USERS = 'users';                     // hash: lower(account) -> JSON { account, salt, hash, created, updated }
const SESS_TTL = 60 * 60 * 24 * 180;       // a device stays signed in for 180 days
const MAX_FAILS = 5;                       // wrong PINs allowed ...
const LOCK_SEC = 15 * 60;                  // ... before the account is locked for 15 minutes
const ACC_RE = /^[A-Za-z0-9_]{1,40}$/;

/* ---------- Redis (REST, no library needed) ---------- */
async function cmd(...args) {
  if (!URL_ || !TOKEN) throw new Error('Redis env vars missing');
  const r = await fetch(URL_, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(args.map(String)),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}

// many commands in one round trip (Upstash /pipeline)
async function pipe(cmds) {
  if (!cmds.length) return [];
  if (!URL_ || !TOKEN) throw new Error('Redis env vars missing');
  const r = await fetch(URL_.replace(/\/$/, '') + '/pipeline', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmds.map(c => c.map(String))),
  });
  const j = await r.json();
  if (!Array.isArray(j)) throw new Error((j && j.error) || 'Pipeline failed');
  return j.map(x => { if (x.error) throw new Error(x.error); return x.result; });
}

async function scanKeys(pattern) {
  let cur = '0';
  const out = [];
  do {
    const [next, keys] = await cmd('SCAN', cur, 'MATCH', pattern, 'COUNT', 500);
    cur = String(next);
    out.push(...keys);
  } while (cur !== '0');
  return out;
}

/* ---------- helpers ---------- */
const same = (a, b) => {
  if (!a || !b) return false;
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const roleOf = pw =>
  same(pw, process.env.ADMIN_PASSWORD) ? 'admin' :
  same(pw, process.env.FAN_PASSWORD) ? 'fan' : null;

const fmtTs = t => new Date(t).toLocaleString('sv-SE', { timeZone: 'Asia/Bangkok' });
const key = v => v.account.toLowerCase() + '|' + v.app;
const bad = message => ({ ok: false, message });
const cleanAcc = v => String(v || '').trim().replace(/^@+/, '');

function checkEntry(account, app, count) {
  if (!/^[A-Za-z0-9_]{1,40}$/.test(account)) return 'Invalid Twitter account.';
  if (!APPS.includes(app)) return 'Invalid app.';
  if (!Number.isInteger(count) || count < 1 || count > 1e9) return 'Please enter a valid vote count.';
  return null;
}

async function loadAll() {
  const flat = (await cmd('HGETALL', HASH)) || [];
  const list = [];
  for (let i = 1; i < flat.length; i += 2) list.push(JSON.parse(flat[i]));
  return list.sort((a, b) => b.t - a.t || b.id - a.id); // newest first
}

function latestMap(list) {
  const m = new Map();
  for (const v of list) if (!m.has(key(v))) m.set(key(v), v);
  return m;
}

function summaryFor(list, account) {
  const byApp = Object.fromEntries(APPS.map(a => [a, 0]));
  let total = 0;
  for (const v of latestMap(list).values()) {
    if (v.account.toLowerCase() !== account.toLowerCase()) continue;
    byApp[v.app] += v.count; total += v.count;
  }
  return { total, byApp };
}

async function adminData(role) {
  const list = await loadAll();
  const lm = latestMap(list);
  const shape = v => ({ row: v.id, account: v.account, app: v.app, count: v.count, ts: fmtTs(v.t) });
  return {
    ok: true,
    role,
    latest: [...lm.values()].map(shape),
    rows: list.map(v => ({ ...shape(v), latest: lm.get(key(v)) === v })),
  };
}

/* ---------- PIN + session helpers ---------- */
const lc = a => String(a || '').toLowerCase();
const isPin = p => /^\d{4}$/.test(String(p == null ? '' : p));
const AUTH_ERR = { ok: false, code: 'AUTH', message: 'Please sign in again.' };
const MISMATCH = { ok: false, code: 'MISMATCH', message: 'Not allowed.' };

async function hashPin(pin, salt) {
  const buf = await scrypt(String(pin), salt + (process.env.PIN_PEPPER || ''), 32);
  return buf.toString('hex');
}
async function getUser(acc) {
  const raw = await cmd('HGET', USERS, lc(acc));
  return raw ? JSON.parse(raw) : null;
}
async function makeRecord(account, pin, prev) {
  const salt = crypto.randomBytes(16).toString('hex');
  return {
    account: prev ? prev.account : account,
    salt,
    hash: await hashPin(pin, salt),
    created: prev ? prev.created : Date.now(),
    updated: Date.now(),
  };
}
async function newSession(u) {
  const token = crypto.randomBytes(24).toString('hex');           // 48 hex chars
  const k = 'usess:' + lc(u.account);
  await pipe([['SET', 'sess:' + token, lc(u.account), 'EX', SESS_TTL], ['SADD', k, token], ['EXPIRE', k, SESS_TTL]]);
  return token;
}
async function revokeSessions(acc, keep) {
  const k = 'usess:' + lc(acc);
  const toks = ((await cmd('SMEMBERS', k)) || []).filter(t => t !== keep);
  if (toks.length) await pipe([...toks.map(t => ['DEL', 'sess:' + t]), ['SREM', k, ...toks]]);
}
async function sessionUser(token) {
  if (!/^[a-f0-9]{48}$/.test(String(token || ''))) return null;
  const acc = await cmd('GET', 'sess:' + token);
  return acc ? getUser(acc) : null;
}
async function lockLeft(acc) {                                     // seconds, 0 = not locked
  const k = 'pinfail:' + lc(acc);
  if (Number((await cmd('GET', k)) || 0) < MAX_FAILS) return 0;
  const t = Number(await cmd('TTL', k));
  return t > 0 ? t : LOCK_SEC;
}
// returns null when the PIN is right, otherwise an error response
async function checkPin(u, pin) {
  const left = await lockLeft(u.account);
  if (left) return bad(`Too many attempts. Try again in ${Math.ceil(left / 60)} min.`);
  if (!isPin(pin)) return bad('PIN must be 4 digits.');
  if (same(await hashPin(pin, u.salt), u.hash)) { await cmd('DEL', 'pinfail:' + lc(u.account)); return null; }
  const k = 'pinfail:' + lc(u.account);
  const n = Number(await cmd('INCR', k));
  if (n === 1 || n >= MAX_FAILS) await cmd('EXPIRE', k, LOCK_SEC);
  const rem = MAX_FAILS - n;
  return bad(rem > 0
    ? `Incorrect PIN. ${rem} attempt${rem === 1 ? '' : 's'} left.`
    : `Too many attempts. Try again in ${LOCK_SEC / 60} min.`);
}
async function hasData(acc) {                                      // account used the app before PINs existed
  if (Number(await cmd('EXISTS', ciKey(acc)))) return true;
  const a = lc(acc);
  return (await loadAll()).some(v => lc(v.account) === a);
}

/* ---------- today feed + check-in helpers ---------- */
const TZ = 'Asia/Bangkok';
const dayOf = t => new Date(t).toLocaleDateString('sv-SE', { timeZone: TZ });
const timeOf = t => new Date(t).toLocaleTimeString('sv-SE', { timeZone: TZ, hour: '2-digit', minute: '2-digit' });
const ciKey = a => 'checkin:' + a.toLowerCase();

// apps this account has updated, grouped by day (YYYY-MM-DD, Bangkok time)
async function appsByDay(account) {
  const list = await loadAll();
  const acc = account.toLowerCase();
  const sets = {};
  for (const v of list) {
    if (v.account.toLowerCase() !== acc) continue;
    (sets[dayOf(v.t)] = sets[dayOf(v.t)] || new Set()).add(v.app);
  }
  const history = {};
  for (const d of Object.keys(sets)) history[d] = APPS.filter(a => sets[d].has(a));
  return history;
}

async function checkinData(account, fresh) {
  const days = ((await cmd('SMEMBERS', ciKey(account))) || []).sort();
  const set = new Set(days);
  const today = dayOf(Date.now());
  const d = new Date(today + 'T00:00:00Z');
  if (!set.has(today)) d.setUTCDate(d.getUTCDate() - 1);
  let streak = 0;
  while (set.has(d.toISOString().slice(0, 10))) { streak++; d.setUTCDate(d.getUTCDate() - 1); }

  const history = await appsByDay(account);
  const apps = history[today] || [];
  return { ok: true, account, days, today, streak, fresh: !!fresh, apps, history };
}

/* ---------- actions ---------- */
const actions = {
  async submitVote(token, acc, app, cnt) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    if (lc(cleanAcc(acc)) !== lc(me.account)) return MISMATCH;
    const account = me.account;
    const count = Math.floor(Number(cnt));
    const err = checkEntry(account, app, count);
    if (err) return bad(err);

    const list = await loadAll();
    const prevRec = latestMap(list).get(account.toLowerCase() + '|' + app);
    const id = Number(await cmd('INCR', SEQ));
    const rec = { id, account, app, count, t: Date.now() };
    await cmd('HSET', HASH, id, JSON.stringify(rec));

    const res = { ok: true, account, app, count, prev: prevRec ? prevRec.count : null };
    if (account === SPECIAL) res.summary = summaryFor([rec, ...list], account);
    return res;
  },

  async getAccountSummary(token, acc) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    const account = me.account;
    if (account !== SPECIAL || lc(cleanAcc(acc)) !== lc(account)) return bad('Not available.');
    return { ok: true, summary: summaryFor(await loadAll(), account) };
  },

  async getTodayFeed() {
    const today = dayOf(Date.now());
    const items = [...latestMap(await loadAll()).values()]
      .filter(v => dayOf(v.t) === today)
      .sort((a, b) => a.t - b.t || a.id - b.id)
      .map(v => ({ id: v.id, account: v.account, app: v.app, time: timeOf(v.t) }));
    return { ok: true, items };
  },

  async getOverview() {
    const list = await loadAll(); // newest first
    const now = Date.now();
    const days = [0, 1, 2].map(i => dayOf(now - i * 86400000)); // today, yesterday, 2 days ago
    const everyone = new Set(), todayPeople = new Set();
    for (const v of list) {
      const a = v.account.toLowerCase();
      everyone.add(a);
      if (dayOf(v.t) === days[0]) todayPeople.add(a);
    }
    const history = list
      .filter(v => days.includes(dayOf(v.t)))
      .slice(0, 600)
      .map(v => ({ id: v.id, account: v.account, app: v.app, day: dayOf(v.t), time: timeOf(v.t) }));
    return { ok: true, today: todayPeople.size, total: everyone.size, days, history };
  },

  async checkIn(token, acc) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    if (lc(cleanAcc(acc)) !== lc(me.account)) return MISMATCH;
    const account = me.account;
    const added = Number(await cmd('SADD', ciKey(account), dayOf(Date.now())));
    return checkinData(account, added === 1);
  },

  async getCheckins(token, acc) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    if (lc(cleanAcc(acc)) !== lc(me.account)) return MISMATCH;
    const account = me.account;
    return checkinData(account, false);
  },

  /* ----- accounts: register / login / PIN ----- */
  async checkAccount(acc) {
    const account = cleanAcc(acc);
    if (!ACC_RE.test(account)) return bad('Invalid Twitter account.');
    if (await getUser(account)) return { ok: true, exists: true, legacy: false };
    return { ok: true, exists: false, legacy: await hasData(account) };
  },

  async register(acc, pin) {
    const account = cleanAcc(acc);
    if (!ACC_RE.test(account)) return bad('Invalid Twitter account.');
    if (!isPin(pin)) return bad('PIN must be 4 digits.');
    const u = await makeRecord(account, pin, null);
    // HSETNX: only the first person to claim a name gets it
    if (!Number(await cmd('HSETNX', USERS, lc(account), JSON.stringify(u)))) {
      return { ok: false, code: 'EXISTS', message: 'This account already has a PIN. Please log in.' };
    }
    return { ok: true, account: u.account, token: await newSession(u) };
  },

  async login(acc, pin) {
    const account = cleanAcc(acc);
    if (!ACC_RE.test(account)) return bad('Invalid Twitter account.');
    const u = await getUser(account);
    if (!u) return bad('Account not found.');
    const err = await checkPin(u, pin);
    if (err) return err;
    return { ok: true, account: u.account, token: await newSession(u) };
  },

  async whoami(token) {
    const me = await sessionUser(token);
    return me ? { ok: true, account: me.account } : AUTH_ERR;
  },

  async logout(token) {
    if (/^[a-f0-9]{48}$/.test(String(token || ''))) {
      const acc = await cmd('GET', 'sess:' + token);
      await cmd('DEL', 'sess:' + token);
      if (acc) await cmd('SREM', 'usess:' + acc, token);
    }
    return { ok: true };
  },

  async changePin(token, oldPin, newPin) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    if (!isPin(newPin)) return bad('PIN must be 4 digits.');
    const err = await checkPin(me, oldPin);
    if (err) return err;
    await cmd('HSET', USERS, lc(me.account), JSON.stringify(await makeRecord(me.account, newPin, me)));
    await revokeSessions(me.account, token);                       // other devices must sign in again
    return { ok: true };
  },

  /* ----- admin: user management ----- */
  async adminListUsers(pw) {
    if (roleOf(pw) !== 'admin') return bad('Incorrect password');
    const [list, usersFlat, ciKeys, failKeys] = await Promise.all([
      loadAll(), cmd('HGETALL', USERS), scanKeys('checkin:*'), scanKeys('pinfail:*'),
    ]);
    const m = new Map();
    const row = acc => {
      const k = lc(acc);
      if (!m.has(k)) m.set(k, { account: acc, hasPin: false, created: 0, apps: 0, entries: 0, last: 0, checkins: 0, locked: false });
      return m.get(k);
    };
    for (let i = 1; i < (usersFlat || []).length; i += 2) {
      const u = JSON.parse(usersFlat[i]);
      Object.assign(row(u.account), { account: u.account, hasPin: true, created: u.created });
    }
    for (const v of list) { const r = row(v.account); r.entries++; r.last = Math.max(r.last, v.t); }
    for (const v of latestMap(list).values()) row(v.account).apps++;

    const counts = await pipe(ciKeys.map(k => ['SCARD', k]));
    ciKeys.forEach((k, i) => { row(k.slice('checkin:'.length)).checkins = Number(counts[i]); });
    const fails = await pipe(failKeys.map(k => ['GET', k]));
    failKeys.forEach((k, i) => { if (Number(fails[i]) >= MAX_FAILS && m.has(k.slice('pinfail:'.length))) m.get(k.slice('pinfail:'.length)).locked = true; });

    const users = [...m.values()]
      .sort((a, b) => (b.last || b.created) - (a.last || a.created) || a.account.localeCompare(b.account))
      .map(r => ({ ...r, created: r.created ? fmtTs(r.created) : '', last: r.last ? fmtTs(r.last) : '' }));
    return { ok: true, users };
  },

  async adminGetUser(pw, acc) {
    if (roleOf(pw) !== 'admin') return bad('Incorrect password');
    const account = cleanAcc(acc);
    if (!ACC_RE.test(account)) return bad('Invalid Twitter account.');
    const [u, list, days, left] = await Promise.all([
      getUser(account), loadAll(), cmd('SMEMBERS', ciKey(account)), lockLeft(account),
    ]);
    const mine = list.filter(v => lc(v.account) === lc(account));       // newest first
    const latest = [...latestMap(mine).values()].map(v => ({ app: v.app, count: v.count, ts: fmtTs(v.t) }));
    return {
      ok: true,
      account: u ? u.account : (mine[0] ? mine[0].account : account),
      hasPin: !!u,
      created: u ? fmtTs(u.created) : '',
      locked: Math.ceil(left / 60),
      latest,
      entries: mine.length,
      checkins: (days || []).length,
      last: mine[0] ? fmtTs(mine[0].t) : '',
    };
  },

  // pin = 4 digits -> set it; pin = '' / null -> clear it (the fan picks a new one at next sign-in)
  async adminSetPin(pw, acc, pin) {
    if (roleOf(pw) !== 'admin') return bad('Incorrect password');
    const account = cleanAcc(acc);
    if (!ACC_RE.test(account)) return bad('Invalid Twitter account.');
    const clear = pin === null || pin === undefined || pin === '';
    if (!clear && !isPin(pin)) return bad('PIN must be 4 digits.');
    if (clear) await cmd('HDEL', USERS, lc(account));
    else await cmd('HSET', USERS, lc(account), JSON.stringify(await makeRecord(account, pin, await getUser(account))));
    await revokeSessions(account);                                    // every device signs in again
    await cmd('DEL', 'pinfail:' + lc(account));                      // also lifts a lock
    return { ok: true, hasPin: !clear };
  },

  async adminDeleteUser(pw, acc, purge) {
    if (roleOf(pw) !== 'admin') return bad('Incorrect password');
    const account = cleanAcc(acc);
    if (!ACC_RE.test(account)) return bad('Invalid Twitter account.');
    await cmd('HDEL', USERS, lc(account));
    await revokeSessions(account);
    await cmd('DEL', 'pinfail:' + lc(account));
    if (purge) {
      await cmd('DEL', ciKey(account));
      const ids = (await loadAll()).filter(v => lc(v.account) === lc(account)).map(v => v.id);
      for (let i = 0; i < ids.length; i += 200) await cmd('HDEL', HASH, ...ids.slice(i, i + 200));
    }
    return { ok: true };
  },

  async getAdminData(pw) {
    const role = roleOf(pw);
    return role ? adminData(role) : bad('Incorrect password');
  },

  async adminEditRow(pw, ref, next) {
    if (roleOf(pw) !== 'admin') return bad('Incorrect password');
    const raw = await cmd('HGET', HASH, ref && ref.row);
    if (!raw) return bad('Entry not found. Please refresh.');
    const cur = JSON.parse(raw);

    const account = cleanAcc(next && next.account);
    const count = Math.floor(Number(next && next.count));
    const err = checkEntry(account, next && next.app, count);
    if (err) return bad(err);

    await cmd('HSET', HASH, cur.id, JSON.stringify({ ...cur, account, app: next.app, count }));
    return adminData('admin');
  },

  async adminDeleteRow(pw, ref) {
    if (roleOf(pw) !== 'admin') return bad('Incorrect password');
    await cmd('HDEL', HASH, ref && ref.row);
    return adminData('admin');
  },
};

/* ---------- handler ---------- */
module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json(bad('Method not allowed'));
  try {
    const { action, args } = req.body || {};
    if (!Object.prototype.hasOwnProperty.call(actions, action)) return res.status(400).json(bad('Unknown action'));
    const out = await actions[action](...(Array.isArray(args) ? args : []));
    return res.status(200).json(out);
  } catch (e) {
    console.error(e);
    return res.status(500).json(bad('Server error'));
  }
};
