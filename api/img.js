/* GET /api/img?u=<account>&v=<version>  -> profile photo
   GET /api/img?id=<post or comment id>  -> post / comment photo
   Photos are stored in Redis as base64 jpeg by rpc.js (avatar:<account> and cimg:<id>). */
const URL_ = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;

module.exports = async function handler(req, res) {
  try {
    const { u, id } = req.query || {};
    let key = null;
    if (u && /^[A-Za-z0-9_]{1,40}$/.test(String(u))) key = 'avatar:' + String(u).toLowerCase();
    else if (id && /^\d{1,12}$/.test(String(id))) key = 'cimg:' + id;
    if (!key) return res.status(400).end();
    if (!URL_ || !TOKEN) return res.status(500).end();

    const r = await fetch(URL_, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
      body: JSON.stringify(['GET', key]),
    });
    const j = await r.json();
    if (!j || !j.result) return res.status(404).end();

    res.setHeader('Content-Type', 'image/jpeg');
    // profile photos are versioned (&v=...), post/comment photos never change once posted
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    return res.status(200).send(Buffer.from(String(j.result), 'base64'));
  } catch (e) {
    console.error(e);
    return res.status(500).end();
  }
};
