const crypto = require('node:crypto');
const { promisify } = require('node:util');
const scrypt = promisify(crypto.scrypt);

const URL_ = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;

const APPS = ['IDOLCHAMP', 'LINC / TIN', 'MUBEAT', 'COOGOONG', 'HIGHER', 'MUNIVERSE'];
/* FOCUS APPS: only these apps are open for updates and count toward XP / levels.
   Keep in sync with FOCUS_APPS in index.html. Leave [] to open every app again.
   Old data for the other apps is kept (not deleted); it is just ignored until they open. */
const FOCUS_APPS = ['IDOLCHAMP', 'MUBEAT', 'LINC / TIN'];
const isFocus = a => !FOCUS_APPS.length || FOCUS_APPS.includes(a);
const OPEN_APPS = APPS.filter(isFocus);
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
// 'tok:<session token>' -> signed-in admin ACCOUNT (no password needed); otherwise the admin / fan password
const roleOf = async pw => {
  const s = String(pw == null ? '' : pw);
  if (s.startsWith('tok:')) {
    const u = await sessionUser(s.slice(4));
    return u && isAdminAcc(u.account) ? 'admin' : null;
  }
  return same(s, process.env.ADMIN_PASSWORD) ? 'admin' :
    same(s, process.env.FAN_PASSWORD) ? 'fan' : null;
};

const fmtTs = t => new Date(t + 7 * 36e5).toISOString().replace('T', ' ').slice(0, 19);   // Thai time, same text as before, no Intl (saves CPU)
const key = v => v.account.toLowerCase() + '|' + v.app;
const bad = message => ({ ok: false, message });
const cleanAcc = v => String(v || '').trim().replace(/^@+/, '');

function checkEntry(account, app, count) {
  if (!/^[A-Za-z0-9_]{1,40}$/.test(account)) return 'Invalid Twitter account.';
  if (!APPS.includes(app)) return 'Invalid app.';
  if (!Number.isInteger(count) || count < 1 || count > 1e9) return 'Please enter a valid vote count.';
  return null;
}

/* In-memory cache (lives as long as the warm serverless instance, shared by concurrent requests).
   loadAll() reads + parses EVERY vote record, so without this each poll from each open tab repeats it.
   Callers must treat the returned list as read-only. Writes use loadAll(true) / dropAll(). */
const ALL_TTL = 30000;                       // ms
let _all = null, _allAt = 0, _allP = null;
async function loadAll(fresh) {
  if (!fresh) {
    if (_all && Date.now() - _allAt < ALL_TTL) return _all;
    if (_allP) return _allP;                // another request is already loading it: wait for the same read
  }
  const p = (async () => {
    const flat = (await cmd('HGETALL', HASH)) || [];
    const list = [];
    for (let i = 1; i < flat.length; i += 2) list.push(JSON.parse(flat[i]));
    list.sort((a, b) => b.t - a.t || b.id - a.id); // newest first
    _all = list; _allAt = Date.now();
    return list;
  })();
  if (!fresh) _allP = p;
  try { return await p; } finally { if (_allP === p) _allP = null; }
}
const dropAll = () => { _all = null; _allP = null; memoDrop(); };

// tiny result cache for read-only actions that are the same for everybody
const _memo = new Map();
async function memo(name, ttl, fn) {
  const hit = _memo.get(name);
  if (hit && Date.now() - hit.at < ttl) return hit.v;
  if (hit && hit.p) return hit.p;
  const p = fn().then(v => { _memo.set(name, { at: Date.now(), v }); return v; }, e => { _memo.delete(name); throw e; });
  _memo.set(name, { at: hit ? hit.at : 0, v: hit ? hit.v : undefined, p });
  return p;
}
const _lv = new Map();                                  // account -> { at, v }  (XP / level cache)
const memoDrop = () => { _memo.clear(); _lv.clear(); };

function latestMap(list) {
  const m = new Map();
  for (const v of list) if (!m.has(key(v))) m.set(key(v), v);
  return m;
}

function summaryFor(list, account) {
  const byApp = Object.fromEntries(APPS.map(a => [a, 0]));
  let total = 0;
  for (const v of latestMap(list).values()) {
    if (v.account.toLowerCase() !== account.toLowerCase() || !isFocus(v.app)) continue;
    byApp[v.app] += v.count; total += v.count;
  }
  return { total, byApp };
}

async function adminData(role) {
  const list = await loadAll(true);
  const lm = latestMap(list);
  const shape = v => ({ row: v.id, account: v.account, app: v.app, count: v.count, ...(v.tickets != null ? { tickets: v.tickets } : {}), ts: fmtTs(v.t) });
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
const TZ = 'Asia/Bangkok';                  // clock shown to people (Thai time)
const DAY_TZ = 'Asia/Seoul';                // a "day" starts at midnight Korea time = 22:00 Thai, like the voting apps
const dayOf = t => new Date(t + 9 * 36e5).toISOString().slice(0, 10);       // Korea day (UTC+9), no Intl (saves CPU)
const timeOf = t => new Date(t + 7 * 36e5).toISOString().slice(11, 16);     // Thai HH:MM, no Intl (saves CPU)
const ciKey = a => 'checkin:' + a.toLowerCase();

// apps this account has updated, grouped by day (YYYY-MM-DD, Korea time)
async function appsByDay(account) {
  const list = await loadAll();
  const acc = account.toLowerCase();
  const sets = {};
  for (const v of list) {
    if (v.account.toLowerCase() !== acc || !isFocus(v.app)) continue;
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


/* ---------- levels (XP) ---------- */
const XP_RULES = { checkin: 20, app: 10, full: 20 };     // check-in day / each app updated that day / all-apps bonus
const LV_AT = [0, 100, 300, 600, 1000, 1500, 2100, 2800, 3600, 4500];   // XP needed to reach LV.1 ... LV.10

function levelOf(xp) {
  let lv = 0;
  for (let i = 0; i < LV_AT.length; i++) if (xp >= LV_AT[i]) lv = i;
  const max = lv === LV_AT.length - 1;
  const from = LV_AT[lv], to = max ? from : LV_AT[lv + 1];
  return { xp, level: lv + 1, from, to, max, pct: max ? 100 : Math.floor(((xp - from) / (to - from)) * 100) };
}

// XP for several accounts at once (one read of the votes, one pipeline for the check-in sets)
async function levelsFor(accounts) {
  const all = [...new Set(accounts.map(lc))];
  const out = {}, miss = [], now = Date.now();
  for (const a of all) {
    const h = _lv.get(a);
    if (h && now - h.at < 60000) out[a] = h.v; else miss.push(a);
  }
  if (miss.length) {
    const fresh = await levelsCompute(miss);
    for (const a of miss) { out[a] = fresh[a]; _lv.set(a, { at: now, v: fresh[a] }); }
  }
  return out;
}
async function levelsCompute(accounts) {
  const want = [...new Set(accounts.map(lc))];
  const out = {};
  if (!want.length) return out;
  const [list, ci] = await Promise.all([loadAll(), pipe(want.map(a => ['SMEMBERS', ciKey(a)]))]);
  const per = {};
  want.forEach(a => { per[a] = {}; });
  for (const v of list) {
    const a = lc(v.account);
    if (!per[a] || !isFocus(v.app)) continue;          // apps that are not open yet give no XP
    const d = dayOf(v.t);
    (per[a][d] = per[a][d] || new Set()).add(v.app);        // an app counts once per day
  }
  want.forEach((a, i) => {
    let xp = (ci[i] || []).length * XP_RULES.checkin;
    for (const s of Object.values(per[a])) {
      xp += s.size * XP_RULES.app;
      if (s.size >= OPEN_APPS.length) xp += XP_RULES.full;
    }
    out[a] = levelOf(xp);
  });
  return out;
}

// profile-photo version per account (hash "avs": lower(account) -> timestamp); 0 = no photo
async function avatarsFor(accounts) {
  const want = [...new Set(accounts.map(lc))];
  const out = {};
  if (!want.length) return out;
  const vs = (await cmd('HMGET', 'avs', ...want)) || [];
  want.forEach((a, i) => { out[a] = Number(vs[i]) || 0; });
  return out;
}
const AV_MAX = 80000;            // base64 characters (~60 KB jpeg)

/* ---------- community ---------- */
const CHAT_ON = false;            // chat room switched off (saves CPU). Set true to open it again (also CHAT_ON in index.html)
const KINDS = ['chat', 'ask', 'share'];
const C_POSTS = 'cposts', C_SEQ = 'cposts:seq', C_FEED = 'cfeed';
const POST_MAX = 1000, CMT_MAX = 300;
const IMG_MAX = 450000;          // base64 characters (~330 KB jpeg)
const PAGE = 12;
const ANN = 'cann', ANN_SEQ = 'cann:seq', ANN_READ = 'cann:read';   // announcements: id -> JSON, counter, account -> last id read
const ANN_MAX = 500, ANN_KEEP = 50;
const CHAT = 'cchat', CHAT_M = 'cchat:m', CHAT_SEQ = 'cchat:seq';   // chat room: ids (zset), id -> JSON, counter
const CHAT_MAX = 300, CHAT_KEEP = 500, CHAT_FIRST = 50;
const C_SEEN = 'cseen';          // account -> time (ms) it last looked at the Community tab (drives the unread number)
const LIKERS_PUBLIC = false;      // true = every signed-in fan can see who liked; false = admins only
const REPORT_HIDE = 3;           // this many different reports hide a post from the feed
// admin accounts (lower-case). Edit this list, or set ADMIN_ACCOUNTS=name1,name2 in Vercel.
const ADMINS = (process.env.ADMIN_ACCOUNTS || 'markleevotingth').split(',').map(x => x.trim().toLowerCase()).filter(Boolean);
const isAdminAcc = a => ADMINS.includes(lc(a));
const isId = v => /^\d{1,12}$/.test(String(v == null ? '' : v));

async function rateOk(acc, what, max, sec) {
  const k = 'crate:' + what + ':' + lc(acc);
  const n = Number(await cmd('INCR', k));
  if (n === 1) await cmd('EXPIRE', k, sec);
  return n <= max;
}

// all announcements, newest first (cached 30 s per instance; annPost / annDelete clear it)
const annAll = () => memo('annAll', 30000, async () => {
  const flat = (await cmd('HGETALL', ANN)) || [];
  const items = [];
  for (let i = 1; i < flat.length; i += 2) { try { items.push(JSON.parse(flat[i])); } catch (e) { /* skip bad row */ } }
  return items.sort((x, y) => y.id - x.id);
});

async function shapePosts(ids, me) {
  if (!ids.length) return [];
  const raws = (await cmd('HMGET', C_POSTS, ...ids)) || [];
  const posts = raws.filter(Boolean).map(r => JSON.parse(r));
  if (!posts.length) return [];
  const meta = await pipe(posts.flatMap(p => [
    ['SCARD', 'clikes:' + p.id], ['HLEN', 'ccm:' + p.id], ['SISMEMBER', 'clikes:' + p.id, lc(me.account)],
  ]));
  const lv = await levelsFor(posts.map(p => p.account));
  const av = await avatarsFor(posts.map(p => p.account));
  return posts.map((p, i) => ({
    id: p.id, account: p.account, kind: p.kind, text: p.text, img: !!p.img, t: p.t, annId: p.annId || 0,
    likes: Number(meta[i * 3]), comments: Number(meta[i * 3 + 1]), liked: Number(meta[i * 3 + 2]) === 1,
    mine: lc(p.account) === lc(me.account),
    admin: isAdminAcc(p.account),
    canDel: lc(p.account) === lc(me.account) || isAdminAcc(me.account),
    lv: (lv[lc(p.account)] || levelOf(0)).level,
    av: av[lc(p.account)] || 0,
  }));
}

/* ---------- actions ---------- */
const actions = {
  async submitVote(token, acc, app, cnt, tix) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    if (lc(cleanAcc(acc)) !== lc(me.account)) return MISMATCH;
    const account = me.account;
    // MUBEAT records two numbers (heartbeats + tickets); either one may be left blank = keep the previous value
    const blank = v => v === null || v === undefined || String(v).trim() === '';
    const isMB = app === 'MUBEAT';
    let count = isMB && blank(cnt) ? undefined : Math.floor(Number(cnt));
    let tickets;
    if (isMB) {
      if (!blank(tix)) {
        tickets = Math.floor(Number(tix));
        if (!Number.isInteger(tickets) || tickets < 0 || tickets > 1e9) return bad('Please enter a valid ticket count.');
      }
      if (count === undefined && tickets === undefined) return bad('Please enter heartbeats or tickets.');
    }
    const err = checkEntry(account, app, count === undefined ? 1 : count);
    if (err) return bad(err);
    if (!isFocus(app)) return bad('This app is not open for updates yet.');

    const list = await loadAll(true);
    const prevRec = latestMap(list).get(account.toLowerCase() + '|' + app);
    if (isMB) {
      if (count === undefined) count = prevRec ? prevRec.count : 0;
      if (tickets === undefined && prevRec && prevRec.tickets != null) tickets = prevRec.tickets;
    }
    const id = Number(await cmd('INCR', SEQ));
    const rec = { id, account, app, count, t: Date.now() };
    if (tickets !== undefined) rec.tickets = tickets;
    await cmd('HSET', HASH, id, JSON.stringify(rec));
    if (_all) _all = [rec, ..._all]; memoDrop();

    const res = { ok: true, account, app, count, tickets: tickets === undefined ? null : tickets, prev: prevRec ? prevRec.count : null, prevTickets: prevRec && prevRec.tickets != null ? prevRec.tickets : null };
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

  getTodayFeed() { return memo('feed', 30000, () => this._feed()); },

  async _feed() {
    const today = dayOf(Date.now());
    const items = [...latestMap(await loadAll()).values()]
      .filter(v => dayOf(v.t) === today && isFocus(v.app))
      .sort((a, b) => a.t - b.t || a.id - b.id)
      .map(v => ({ id: v.id, account: v.account, app: v.app, time: timeOf(v.t) }));
    // community posts + admin announcements from today (shown in Recent Activity next to the vote updates)
    const community = [];
    try {
      const ids = (await cmd('ZREVRANGE', C_FEED, 0, 29)) || [];
      const raws = ids.length ? ((await cmd('HMGET', C_POSTS, ...ids)) || []) : [];
      raws.filter(Boolean).forEach(r => {
        const p = JSON.parse(r);
        if (p.kind !== 'ann' && dayOf(p.t) === today) community.push({ id: 'p' + p.id, c: 'post', account: p.account, time: timeOf(p.t), ts: p.t });
      });
      const flat = (await cmd('HGETALL', ANN)) || [];
      for (let i = 1; i < flat.length; i += 2) {
        const a = JSON.parse(flat[i]);
        if (dayOf(a.t) === today) community.push({ id: 'a' + a.id, c: 'ann', account: a.account, time: timeOf(a.t), ts: a.t });
      }
      community.sort((x, y) => x.ts - y.ts);
    } catch (e) { console.error(e); }
    return { ok: true, items, community };
  },

  getOverview() { return memo('overview', 60000, () => this._overview()); },

  async _overview() {
    const list = await loadAll(); // newest first
    const now = Date.now();
    const days = [0, 1, 2].map(i => dayOf(now - i * 86400000)); // today, yesterday, 2 days ago
    const everyone = new Set(), todayPeople = new Set();
    for (const v of list) {
      const a = v.account.toLowerCase();
      everyone.add(a);
      if (dayOf(v.t) === days[0] && isFocus(v.app)) todayPeople.add(a);
    }
    const history = list
      .filter(v => days.includes(dayOf(v.t)) && isFocus(v.app))
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
    _lv.clear();
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

  // the signed-in fan's own profile: the account always comes from the session token, never from the request
  async getMyProfile(token) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    const [list, days] = await Promise.all([loadAll(), cmd('SMEMBERS', ciKey(me.account))]);
    const mine = list.filter(v => lc(v.account) === lc(me.account) && isFocus(v.app));      // newest first (open apps only)
    const latest = [...latestMap(mine).values()].map(v => ({ app: v.app, count: v.count, ...(v.tickets != null ? { tickets: v.tickets } : {}), ts: fmtTs(v.t) }));
    return {
      ok: true,
      account: me.account,
      created: me.created ? fmtTs(me.created) : '',
      latest,
      entries: mine.length,
      checkins: (days || []).length,
      last: mine[0] ? fmtTs(mine[0].t) : '',
    };
  },

  /* ----- level ----- */
  async getMyLevel(token) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    const lv = (await levelsFor([me.account]))[lc(me.account)];
    const av = (await avatarsFor([me.account]))[lc(me.account)];
    return { ok: true, ...lv, rules: XP_RULES, ladder: LV_AT, account: me.account, av };
  },

  // image = jpeg data URL -> set the profile photo; image = '' -> remove it (back to the mascot)
  async setAvatar(token, image) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    const a = lc(me.account);
    if (!image) {
      await pipe([['DEL', 'avatar:' + a], ['HDEL', 'avs', a]]);
      return { ok: true, v: 0 };
    }
    const pre = 'data:image/jpeg;base64,';
    const b64 = String(image).startsWith(pre) ? String(image).slice(pre.length) : '';
    if (!b64 || b64.length > AV_MAX || !b64.startsWith('/9j/') || !/^[A-Za-z0-9+/=]+$/.test(b64)) return bad('Invalid or too large image.');
    if (!(await rateOk(me.account, 'avatar', 10, 3600))) return bad('Too many changes. Please try again later.');
    const v = Date.now();
    await pipe([['SET', 'avatar:' + a, b64], ['HSET', 'avs', a, v]]);
    return { ok: true, v };
  },

  // top fans by XP (admin accounts are not ranked)
  async getLeaderboard(token) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    const rows = await memo('leaderboard', 60000, async () => {
      const flat = (await cmd('HGETALL', USERS)) || [];
      const accs = [];
      for (let i = 1; i < flat.length; i += 2) accs.push(JSON.parse(flat[i]).account);
      const [lv, av] = await Promise.all([levelsFor(accs), avatarsFor(accs)]);
      return accs.filter(a => !isAdminAcc(a))
        .map(a => ({ account: a, xp: lv[lc(a)].xp, level: lv[lc(a)].level, av: av[lc(a)] || 0 }))
        .filter(r => r.xp > 0)
        .sort((a, b) => b.xp - a.xp || a.account.localeCompare(b.account));
    });
    const mine = lc(me.account);
    const idx = rows.findIndex(r => lc(r.account) === mine);
    return { ok: true, top: rows.slice(0, 20).map(r => ({ ...r, me: lc(r.account) === mine })), rank: idx >= 0 ? idx + 1 : 0, total: rows.length };
  },

  /* ----- community ----- */
  async communityList(token, kind, offset) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    const feed = KINDS.includes(kind) ? C_FEED + ':' + kind : C_FEED;
    const off = Math.max(0, Math.floor(Number(offset)) || 0);
    const ids = (await cmd('ZREVRANGE', feed, off, off + PAGE)) || [];      // one extra id tells us there is more
    const page = ids.slice(0, PAGE);
    return { ok: true, more: ids.length > PAGE, next: off + page.length, posts: await shapePosts(page, me) };
  },

  async communityPost(token, kind, text, image) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    kind = KINDS.includes(kind) ? kind : 'chat';
    text = String(text || '').replace(/\r\n/g, '\n').trim();
    if (text.length > POST_MAX) return bad('Post is too long.');

    let b64 = '';
    if (image) {
      const pre = 'data:image/jpeg;base64,';
      b64 = String(image).startsWith(pre) ? String(image).slice(pre.length) : '';
      if (!b64 || b64.length > IMG_MAX || !b64.startsWith('/9j/') || !/^[A-Za-z0-9+/=]+$/.test(b64)) return bad('Invalid or too large image.');
    }
    if (!text && !b64) return bad('Write something first.');
    if (!(await rateOk(me.account, 'post', 10, 3600))) return bad('You are posting too fast. Please try again later.');

    const id = Number(await cmd('INCR', C_SEQ));
    const t = Date.now();
    if (b64) await cmd('SET', 'cimg:' + id, b64);
    const rec = { id, account: me.account, kind, text, img: !!b64, t };
    await pipe([
      ['HSET', C_POSTS, id, JSON.stringify(rec)],
      ['ZADD', C_FEED, t, id],
      ['ZADD', C_FEED + ':' + kind, t, id],
    ]);
    return { ok: true, post: (await shapePosts([String(id)], me))[0] };
  },

  async communityGet(token, id) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    if (!isId(id)) return bad('Post not found.');
    const post = (await shapePosts([String(id)], me))[0];
    if (!post) return bad('Post not found.');
    const flat = (await cmd('HGETALL', 'ccm:' + id)) || [];
    const cms = [];
    for (let i = 1; i < flat.length; i += 2) cms.push(JSON.parse(flat[i]));
    cms.sort((a, b) => a.t - b.t || a.id - b.id);
    const lv = await levelsFor(cms.map(c => c.account));
    const av = await avatarsFor(cms.map(c => c.account));
    return {
      ok: true, post,
      comments: cms.slice(-100).map(c => ({
        id: c.id, account: c.account, text: c.text, t: c.t, img: !!c.img,
        mine: lc(c.account) === lc(me.account), admin: isAdminAcc(c.account), canDel: lc(c.account) === lc(me.account) || isAdminAcc(me.account), lv: (lv[lc(c.account)] || levelOf(0)).level, av: av[lc(c.account)] || 0,
      })),
    };
  },

  async communityComment(token, id, text, image) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    if (!isId(id) || !Number(await cmd('HEXISTS', C_POSTS, id))) return bad('Post not found.');
    text = String(text || '').trim();
    let b64 = '';
    if (image) {
      const pre = 'data:image/jpeg;base64,';
      b64 = String(image).startsWith(pre) ? String(image).slice(pre.length) : '';
      if (!b64 || b64.length > IMG_MAX || !b64.startsWith('/9j/') || !/^[A-Za-z0-9+/=]+$/.test(b64)) return bad('Invalid or too large image.');
    }
    if (!text && !b64) return bad('Write something first.');
    if (text.length > CMT_MAX) return bad('Comment is too long.');
    if (!(await rateOk(me.account, 'cmt', 30, 3600))) return bad('You are commenting too fast. Please try again later.');
    const cid = Number(await cmd('INCR', C_SEQ));        // same counter as posts, so /api/img?id= never clashes
    const c = { id: cid, account: me.account, text, t: Date.now() };
    if (b64) { c.img = true; await cmd('SET', 'cimg:' + cid, b64); }
    await cmd('HSET', 'ccm:' + id, cid, JSON.stringify(c));
    const lv = (await levelsFor([me.account]))[lc(me.account)];
    const av = (await avatarsFor([me.account]))[lc(me.account)];
    return { ok: true, comment: { ...c, img: !!b64, mine: true, admin: isAdminAcc(me.account), canDel: true, lv: lv.level, av } };
  },

  // who liked a post (newest names are not tracked; the list is the set of accounts)
  async communityLikers(token, id) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    if (!LIKERS_PUBLIC && !isAdminAcc(me.account)) return MISMATCH;
    if (!isId(id)) return bad('Post not found.');
    const names = ((await cmd('SMEMBERS', 'clikes:' + id)) || []).map(String).sort();
    // show the account's original spelling when we have it
    let users = names;
    if (names.length) {
      const raws = (await cmd('HMGET', USERS, ...names)) || [];
      users = names.map((n, i) => { try { return raws[i] ? JSON.parse(raws[i]).account : n; } catch (e) { return n; } });
    }
    return { ok: true, users, count: users.length };
  },

  async communityLike(token, id) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    if (!isId(id) || !Number(await cmd('HEXISTS', C_POSTS, id))) return bad('Post not found.');
    const k = 'clikes:' + id, a = lc(me.account);
    const liked = !Number(await cmd('SISMEMBER', k, a));
    await cmd(liked ? 'SADD' : 'SREM', k, a);
    return { ok: true, liked, likes: Number(await cmd('SCARD', k)) };
  },

  // cid given -> delete that comment, otherwise delete the post (only the author can do either)
  async communityDelete(token, id, cid) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    if (!isId(id)) return bad('Post not found.');
    if (cid !== undefined && cid !== null && cid !== '') {
      if (!isId(cid)) return bad('Comment not found.');
      const raw = await cmd('HGET', 'ccm:' + id, cid);
      if (!raw) return { ok: true };
      if (lc(JSON.parse(raw).account) !== lc(me.account) && !isAdminAcc(me.account)) return MISMATCH;
      await pipe([['HDEL', 'ccm:' + id, cid], ['DEL', 'cimg:' + cid]]);
      return { ok: true };
    }
    const raw = await cmd('HGET', C_POSTS, id);
    if (!raw) return { ok: true };
    const p = JSON.parse(raw);
    if (lc(p.account) !== lc(me.account) && !isAdminAcc(me.account)) return MISMATCH;
    const cflat = (await cmd('HGETALL', 'ccm:' + id)) || [];
    const cimgs = [];
    for (let i = 0; i < cflat.length; i += 2) cimgs.push(['DEL', 'cimg:' + cflat[i]]);   // comment photos go with the post
    await pipe([
      ['HDEL', C_POSTS, id], ['ZREM', C_FEED, id], ['ZREM', C_FEED + ':' + p.kind, id],
      ['DEL', 'cimg:' + id], ['DEL', 'clikes:' + id], ['DEL', 'ccm:' + id], ['DEL', 'crep:' + id],
      ...cimgs,
    ]);
    return { ok: true };
  },

  async communityReport(token, id) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    if (!isId(id)) return bad('Post not found.');
    const raw = await cmd('HGET', C_POSTS, id);
    if (!raw) return { ok: true, hidden: true };
    const p = JSON.parse(raw);
    await cmd('SADD', 'crep:' + id, lc(me.account));
    const n = Number(await cmd('SCARD', 'crep:' + id));
    const hidden = n >= REPORT_HIDE;
    if (hidden) await pipe([['ZREM', C_FEED, id], ['ZREM', C_FEED + ':' + p.kind, id]]);
    return { ok: true, hidden };
  },

  /* ----- chat room: short live messages, newest at the bottom ----- */
  async chatList(token, after) {
    if (!CHAT_ON) return bad('Chat is not available yet.');
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    const a = Math.max(0, Math.floor(Number(after)) || 0);
    let ids;
    if (a > 0) ids = (await cmd('ZRANGEBYSCORE', CHAT, '(' + a, '+inf', 'LIMIT', 0, 100)) || [];
    else ids = ((await cmd('ZREVRANGE', CHAT, 0, CHAT_FIRST - 1)) || []).reverse();
    if (!ids.length) return { ok: true, messages: [] };
    const raws = (await cmd('HMGET', CHAT_M, ...ids)) || [];
    const rows = raws.filter(Boolean).map(r => JSON.parse(r));
    const lv = await levelsFor(rows.map(m => m.account));
    const av = await avatarsFor(rows.map(m => m.account));
    const meAdmin = isAdminAcc(me.account);
    return {
      ok: true,
      messages: rows.map(m => ({
        id: m.id, account: m.account, text: m.text, t: m.t,
        mine: lc(m.account) === lc(me.account),
        admin: isAdminAcc(m.account),
        canDel: lc(m.account) === lc(me.account) || meAdmin,
        lv: (lv[lc(m.account)] || levelOf(0)).level,
        av: av[lc(m.account)] || 0,
      })),
    };
  },

  async chatSend(token, text) {
    if (!CHAT_ON) return bad('Chat is not available yet.');
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    text = String(text || '').replace(/\r\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
    if (!text) return bad('Write something first.');
    if (text.length > CHAT_MAX) return bad('Message is too long.');
    if (!(await rateOk(me.account, 'chat', 20, 60))) return bad('You are sending too fast. Please wait a moment.');
    const id = Number(await cmd('INCR', CHAT_SEQ));
    const rec = { id, account: me.account, text, t: Date.now() };
    await pipe([['HSET', CHAT_M, id, JSON.stringify(rec)], ['ZADD', CHAT, id, id], ['HDEL', CHAT_M, id - CHAT_KEEP], ['ZREM', CHAT, id - CHAT_KEEP]]);
    const m = (await actions.chatList(token, id - 1)).messages || [];
    return { ok: true, message: m.find(x => x.id === id) || null };
  },

  async chatDelete(token, id) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    if (!isId(id)) return bad('Not found.');
    const raw = await cmd('HGET', CHAT_M, id);
    if (!raw) return { ok: true };
    if (lc(JSON.parse(raw).account) !== lc(me.account) && !isAdminAcc(me.account)) return MISMATCH;
    await pipe([['HDEL', CHAT_M, id], ['ZREM', CHAT, id]]);
    return { ok: true };
  },

  /* ----- announcements: admins post, everyone reads ----- */
  async annList(token) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    const acc = lc(me.account);
    const [items, rd, sn] = await Promise.all([annAll(), cmd('HGET', ANN_READ, acc), cmd('HGET', C_SEEN, acc)]);
    const list = items.slice(0, ANN_KEEP);
    const last = Number(rd) || 0;
    // community posts newer than the last visit to the Community tab. Own posts and announcement posts are not counted
    // here (announcements keep their own unread count until the bell is opened).
    let pseen = Number(sn) || 0, pnew = 0;
    if (!pseen) { pseen = Date.now() - 24 * 3600 * 1000; await cmd('HSET', C_SEEN, acc, pseen); }   // first time: count the last 24 h
    const ids = (await cmd('ZRANGEBYSCORE', C_FEED, '(' + pseen, '+inf', 'LIMIT', 0, 100)) || [];
    if (ids.length) {
      const raws = (await cmd('HMGET', C_POSTS, ...ids)) || [];
      pnew = raws.filter(Boolean).map(r => JSON.parse(r)).filter(p => p.kind !== 'ann' && lc(p.account) !== acc).length;
    }
    return { ok: true, admin: isAdminAcc(me.account), last, unread: list.filter(x => x.id > last).length, items: list, pnew, pseen };
  },

  async communitySeen(token) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    const t = Date.now();
    await cmd('HSET', C_SEEN, lc(me.account), t);
    return { ok: true, t };
  },

  async annRead(token) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    const seq = Number(await cmd('GET', ANN_SEQ)) || 0;
    await cmd('HSET', ANN_READ, lc(me.account), seq);
    return { ok: true, last: seq };
  },

  async annPost(token, text) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    if (!isAdminAcc(me.account)) return MISMATCH;
    text = String(text || '').replace(/\r\n/g, '\n').trim();
    if (!text) return bad('Write something first.');
    if (text.length > ANN_MAX) return bad('Announcement is too long.');
    if (!(await rateOk(me.account, 'ann', 20, 3600))) return bad('You are posting too fast. Please try again later.');
    const id = Number(await cmd('INCR', ANN_SEQ));
    const pid = Number(await cmd('INCR', C_SEQ));                       // every announcement is also posted to the Community feed
    const t = Date.now();
    const item = { id, text, t, account: me.account, pid };
    const post = { id: pid, account: me.account, kind: 'ann', text, img: false, t, annId: id };
    await pipe([
      ['HSET', ANN, id, JSON.stringify(item)], ['HSET', ANN_READ, lc(me.account), id], ['HDEL', ANN, id - ANN_KEEP],
      ['HSET', C_POSTS, pid, JSON.stringify(post)], ['ZADD', C_FEED, t, pid], ['ZADD', C_FEED + ':ann', t, pid],
    ]);
    memoDrop();
    return { ok: true, item };
  },

  async annDelete(token, id) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    if (!isAdminAcc(me.account)) return MISMATCH;
    if (!isId(id)) return bad('Not found.');
    const raw = await cmd('HGET', ANN, id);
    let pid = 0;
    try { pid = raw ? Number(JSON.parse(raw).pid) || 0 : 0; } catch (e) { /* ignore */ }
    await cmd('HDEL', ANN, id);
    if (pid) await pipe([                                                // remove its Community post too
      ['HDEL', C_POSTS, pid], ['ZREM', C_FEED, pid], ['ZREM', C_FEED + ':ann', pid],
      ['DEL', 'cimg:' + pid], ['DEL', 'clikes:' + pid], ['DEL', 'ccm:' + pid], ['DEL', 'crep:' + pid],
    ]);
    memoDrop();
    return { ok: true };
  },

  /* ----- admin: user management ----- */
  async adminListUsers(pw) {
    if ((await roleOf(pw)) !== 'admin') return bad('Incorrect password');
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
    if ((await roleOf(pw)) !== 'admin') return bad('Incorrect password');
    const account = cleanAcc(acc);
    if (!ACC_RE.test(account)) return bad('Invalid Twitter account.');
    const [u, list, days, left] = await Promise.all([
      getUser(account), loadAll(), cmd('SMEMBERS', ciKey(account)), lockLeft(account),
    ]);
    const mine = list.filter(v => lc(v.account) === lc(account));       // newest first
    const latest = [...latestMap(mine).values()].map(v => ({ app: v.app, count: v.count, ...(v.tickets != null ? { tickets: v.tickets } : {}), ts: fmtTs(v.t) }));
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
    if ((await roleOf(pw)) !== 'admin') return bad('Incorrect password');
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
    if ((await roleOf(pw)) !== 'admin') return bad('Incorrect password');
    const account = cleanAcc(acc);
    if (!ACC_RE.test(account)) return bad('Invalid Twitter account.');
    await cmd('HDEL', USERS, lc(account));
    await revokeSessions(account);
    await cmd('DEL', 'pinfail:' + lc(account));
    if (purge) {
      await cmd('DEL', ciKey(account));
      const ids = (await loadAll(true)).filter(v => lc(v.account) === lc(account)).map(v => v.id);
      for (let i = 0; i < ids.length; i += 200) await cmd('HDEL', HASH, ...ids.slice(i, i + 200));
      dropAll();
    }
    return { ok: true };
  },

  async getAdminData(pw) {
    const role = await roleOf(pw);
    return role ? adminData(role) : bad('Incorrect password');
  },

  async adminEditRow(pw, ref, next) {
    if ((await roleOf(pw)) !== 'admin') return bad('Incorrect password');
    const raw = await cmd('HGET', HASH, ref && ref.row);
    if (!raw) return bad('Entry not found. Please refresh.');
    const cur = JSON.parse(raw);

    const account = cleanAcc(next && next.account);
    const count = Math.floor(Number(next && next.count));
    const err = checkEntry(account, next && next.app, next && next.app === 'MUBEAT' && count === 0 ? 1 : count);   // MUBEAT may have 0 heartbeats (tickets only)
    if (err) return bad(err);

    const upd = { ...cur, account, app: next.app, count };
    if (upd.app !== 'MUBEAT') delete upd.tickets;           // tickets only exist for MUBEAT
    await cmd('HSET', HASH, cur.id, JSON.stringify(upd));
    dropAll();
    return adminData('admin');
  },

  async adminDeleteRow(pw, ref) {
    if ((await roleOf(pw)) !== 'admin') return bad('Incorrect password');
    await cmd('HDEL', HASH, ref && ref.row);
    dropAll();
    return adminData('admin');
  },
};

/* ---------- handler ---------- */
module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json(bad('Method not allowed'));
  try {
    const { action, args } = req.body || {};
    if (typeof action !== 'string' || action[0] === '_' || !Object.prototype.hasOwnProperty.call(actions, action)) return res.status(400).json(bad('Unknown action'));
    const out = await actions[action](...(Array.isArray(args) ? args : []));
    return res.status(200).json(out);
  } catch (e) {
    console.error(e);
    return res.status(500).json(bad('Server error'));
  }
};
