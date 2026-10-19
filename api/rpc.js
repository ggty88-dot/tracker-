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
  const want = [...new Set(accounts.map(lc))];
  const out = {};
  if (!want.length) return out;
  const [list, ci] = await Promise.all([loadAll(), pipe(want.map(a => ['SMEMBERS', ciKey(a)]))]);
  const per = {};
  want.forEach(a => { per[a] = {}; });
  for (const v of list) {
    const a = lc(v.account);
    if (!per[a]) continue;
    const d = dayOf(v.t);
    (per[a][d] = per[a][d] || new Set()).add(v.app);        // an app counts once per day
  }
  want.forEach((a, i) => {
    let xp = (ci[i] || []).length * XP_RULES.checkin;
    for (const s of Object.values(per[a])) {
      xp += s.size * XP_RULES.app;
      if (s.size >= APPS.length) xp += XP_RULES.full;
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
const KINDS = ['chat', 'ask', 'share'];
const C_POSTS = 'cposts', C_SEQ = 'cposts:seq', C_FEED = 'cfeed';
const POST_MAX = 1000, CMT_MAX = 300;
const IMG_MAX = 450000;          // base64 characters (~330 KB jpeg)
const PAGE = 12;
const ANN = 'cann', ANN_SEQ = 'cann:seq', ANN_READ = 'cann:read';   // announcements: id -> JSON, counter, account -> last id read
const ANN_MAX = 500, ANN_KEEP = 50;
const CHAT = 'cchat', CHAT_M = 'cchat:m', CHAT_SEQ = 'cchat:seq';   // chat room: ids (zset), id -> JSON, counter
const CHAT_MAX = 300, CHAT_KEEP = 500, CHAT_FIRST = 50;
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
    id: p.id, account: p.account, kind: p.kind, text: p.text, img: !!p.img, t: p.t,
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
    // community posts + admin announcements from today (shown in Recent Activity next to the vote updates)
    const community = [];
    try {
      const ids = (await cmd('ZREVRANGE', C_FEED, 0, 29)) || [];
      const raws = ids.length ? ((await cmd('HMGET', C_POSTS, ...ids)) || []) : [];
      raws.filter(Boolean).forEach(r => {
        const p = JSON.parse(r);
        if (dayOf(p.t) === today) community.push({ id: 'p' + p.id, c: 'post', account: p.account, time: timeOf(p.t), ts: p.t });
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

  // the signed-in fan's own profile: the account always comes from the session token, never from the request
  async getMyProfile(token) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    const [list, days] = await Promise.all([loadAll(), cmd('SMEMBERS', ciKey(me.account))]);
    const mine = list.filter(v => lc(v.account) === lc(me.account));      // newest first
    const latest = [...latestMap(mine).values()].map(v => ({ app: v.app, count: v.count, ts: fmtTs(v.t) }));
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
    const flat = (await cmd('HGETALL', USERS)) || [];
    const accs = [];
    for (let i = 1; i < flat.length; i += 2) accs.push(JSON.parse(flat[i]).account);
    const [lv, av] = await Promise.all([levelsFor(accs), avatarsFor(accs)]);
    const rows = accs.filter(a => !isAdminAcc(a))
      .map(a => ({ account: a, xp: lv[lc(a)].xp, level: lv[lc(a)].level, av: av[lc(a)] || 0, me: lc(a) === lc(me.account) }))
      .filter(r => r.xp > 0)
      .sort((a, b) => b.xp - a.xp || a.account.localeCompare(b.account));
    const idx = rows.findIndex(r => r.me);
    return { ok: true, top: rows.slice(0, 20), rank: idx >= 0 ? idx + 1 : 0, total: rows.length };
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
        id: c.id, account: c.account, text: c.text, t: c.t,
        mine: lc(c.account) === lc(me.account), admin: isAdminAcc(c.account), canDel: lc(c.account) === lc(me.account) || isAdminAcc(me.account), lv: (lv[lc(c.account)] || levelOf(0)).level, av: av[lc(c.account)] || 0,
      })),
    };
  },

  async communityComment(token, id, text) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    if (!isId(id) || !Number(await cmd('HEXISTS', C_POSTS, id))) return bad('Post not found.');
    text = String(text || '').trim();
    if (!text) return bad('Write something first.');
    if (text.length > CMT_MAX) return bad('Comment is too long.');
    if (!(await rateOk(me.account, 'cmt', 30, 3600))) return bad('You are commenting too fast. Please try again later.');
    const cid = Number(await cmd('INCR', C_SEQ));
    const c = { id: cid, account: me.account, text, t: Date.now() };
    await cmd('HSET', 'ccm:' + id, cid, JSON.stringify(c));
    const lv = (await levelsFor([me.account]))[lc(me.account)];
    const av = (await avatarsFor([me.account]))[lc(me.account)];
    return { ok: true, comment: { ...c, mine: true, admin: isAdminAcc(me.account), canDel: true, lv: lv.level, av } };
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
      await cmd('HDEL', 'ccm:' + id, cid);
      return { ok: true };
    }
    const raw = await cmd('HGET', C_POSTS, id);
    if (!raw) return { ok: true };
    const p = JSON.parse(raw);
    if (lc(p.account) !== lc(me.account) && !isAdminAcc(me.account)) return MISMATCH;
    await pipe([
      ['HDEL', C_POSTS, id], ['ZREM', C_FEED, id], ['ZREM', C_FEED + ':' + p.kind, id],
      ['DEL', 'cimg:' + id], ['DEL', 'clikes:' + id], ['DEL', 'ccm:' + id], ['DEL', 'crep:' + id],
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
    const [flat, rd] = await Promise.all([cmd('HGETALL', ANN), cmd('HGET', ANN_READ, lc(me.account))]);
    const items = [];
    for (let i = 1; i < (flat || []).length; i += 2) { try { items.push(JSON.parse(flat[i])); } catch (e) { /* skip bad row */ } }
    items.sort((x, y) => y.id - x.id);
    const list = items.slice(0, ANN_KEEP);
    const last = Number(rd) || 0;
    return { ok: true, admin: isAdminAcc(me.account), last, unread: list.filter(x => x.id > last).length, items: list };
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
    const item = { id, text, t: Date.now(), account: me.account };
    await pipe([['HSET', ANN, id, JSON.stringify(item)], ['HSET', ANN_READ, lc(me.account), id], ['HDEL', ANN, id - ANN_KEEP]]);
    return { ok: true, item };
  },

  async annDelete(token, id) {
    const me = await sessionUser(token);
    if (!me) return AUTH_ERR;
    if (!isAdminAcc(me.account)) return MISMATCH;
    if (!isId(id)) return bad('Not found.');
    await cmd('HDEL', ANN, id);
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
      const ids = (await loadAll()).filter(v => lc(v.account) === lc(account)).map(v => v.id);
      for (let i = 0; i < ids.length; i += 200) await cmd('HDEL', HASH, ...ids.slice(i, i + 200));
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
    const err = checkEntry(account, next && next.app, count);
    if (err) return bad(err);

    await cmd('HSET', HASH, cur.id, JSON.stringify({ ...cur, account, app: next.app, count }));
    return adminData('admin');
  },

  async adminDeleteRow(pw, ref) {
    if ((await roleOf(pw)) !== 'admin') return bad('Incorrect password');
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
