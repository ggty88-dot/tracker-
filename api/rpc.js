const crypto = require('node:crypto');

const URL_ = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;

const APPS = ['IDOLCHAMP', 'LINC / TIN', 'MUBEAT', 'COOGOONG', 'HIGHER', 'MUNIVERSE'];
const SPECIAL = '10694';
const HASH = 'votes';
const SEQ = 'votes:seq';

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
  async submitVote(acc, app, cnt) {
    const account = cleanAcc(acc);
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

  async getAccountSummary(acc) {
    const account = cleanAcc(acc);
    if (account !== SPECIAL) return bad('Not available.');
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

  async checkIn(acc) {
    const account = cleanAcc(acc);
    if (!/^[A-Za-z0-9_]{1,40}$/.test(account)) return bad('Invalid Twitter account.');
    const added = Number(await cmd('SADD', ciKey(account), dayOf(Date.now())));
    return checkinData(account, added === 1);
  },

  async getCheckins(acc) {
    const account = cleanAcc(acc);
    if (!/^[A-Za-z0-9_]{1,40}$/.test(account)) return bad('Invalid Twitter account.');
    return checkinData(account, false);
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
