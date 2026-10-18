// GET /api/img?id=123  ->  the JPEG attached to community post 123
const URL_ = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;

module.exports = async function handler(req, res) {
  const id = String((req.query && req.query.id) || '');
  if (!/^\d{1,12}$/.test(id)) return res.status(400).end();
  try {
    const r = await fetch(URL_, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
      body: JSON.stringify(['GET', 'cimg:' + id]),
    });
    const j = await r.json();
    if (!j || !j.result) return res.status(404).end();
    res.setHeader('Content-Type', 'image/jpeg');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    return res.status(200).send(Buffer.from(j.result, 'base64'));
  } catch (e) {
    console.error(e);
    return res.status(500).end();
  }
};
