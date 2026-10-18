// GET /api/img?id=123  ->  the JPEG attached to community post 123
// GET /api/img?u=name&v=123 -> the profile photo of account "name" (v = cache-busting version)
const URL_ = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;

module.exports = async function handler(req, res) {
  const q = req.query || {};
  let key = '';
  if (q.u != null && q.u !== '') {
    const u = String(q.u).toLowerCase();
    if (!/^[a-z0-9_]{1,40}$/.test(u)) return res.status(400).end();
    key = 'avatar:' + u;
  } else {
    const id = String(q.id || '');
    if (!/^\d{1,12}$/.test(id)) return res.status(400).end();
    key = 'cimg:' + id;
  }
  try {
    const r = await fetch(URL_, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
      body: JSON.stringify(['GET', key]),
    });
    const j = await r.json();
    if (!j || !j.result) return res.status(404).end();
    res.setHeader('Content-Type', 'image/jpeg');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // avatar URLs carry ?v=timestamp, so they can be cached for a long time
    res.setHeader('Cache-Control', 'public, max-age=86400');
    return res.status(200).send(Buffer.from(j.result, 'base64'));
  } catch (e) {
    console.error(e);
    return res.status(500).end();
  }
};
