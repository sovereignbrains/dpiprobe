// dpiprobe report receiver. POST /v1/report only.
// No CORS. Do not log the body, headers, or the client address.
// RATE is a KV namespace (rate limit, daily salt, and report storage when
// R2 is absent). REPORTS is an R2 bucket, used when it is bound.

const MAX_GZ = 64 * 1024;
const MAX_RAW = 512 * 1024;
const REQUIRED = ["schema", "v", "os", "dur_s", "vpn", "bypass_on", "targets", "domains"];
const ALLOWED = new Set([...REQUIRED, "net", "dns", "tls", "sni_bypass", "quic", "tcp16", "tg"]);
const MAPPED = new Set(["mapped", "mappedaddr", "mapped_addr"]);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method !== "POST" || url.pathname !== "/v1/report") {
      return text(404, "not found");
    }
    const encoding = (request.headers.get("content-encoding") || "").toLowerCase();
    if (encoding !== "gzip") {
      return text(400, "gzip required");
    }
    const len = Number(request.headers.get("content-length") || "0");
    if (len > MAX_GZ) {
      return text(413, "too large");
    }
    const buf = await request.arrayBuffer();
    if (buf.byteLength === 0 || buf.byteLength > MAX_GZ) {
      return text(buf.byteLength > MAX_GZ ? 413 : 400, buf.byteLength > MAX_GZ ? "too large" : "bad gzip");
    }
    let raw;
    try {
      raw = await gunzipLimited(new Uint8Array(buf), MAX_RAW);
    } catch (e) {
      const msg = String(e && e.message) === "large" ? "too large" : "bad gzip";
      return text(msg === "too large" ? 413 : 400, msg);
    }
    const ip = request.headers.get("CF-Connecting-IP") || "";
    let bodyText;
    try {
      bodyText = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    } catch {
      return text(400, "bad json");
    }
    if (ip && bodyText.includes(ip)) {
      return text(400, "addr");
    }
    let body;
    try {
      body = JSON.parse(bodyText);
    } catch {
      return text(400, "bad json");
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return text(400, "bad json");
    }
    if (body.schema !== 1 || badTypes(body)) {
      return text(400, "schema");
    }
    for (const k of Object.keys(body)) {
      if (!ALLOWED.has(k)) {
        return text(400, "keys");
      }
    }
    for (const k of REQUIRED) {
      if (!Object.prototype.hasOwnProperty.call(body, k)) {
        return text(400, "keys");
      }
    }
    if (netHasAddr(body.net) || hasMapped(body)) {
      return text(400, "keys");
    }
    if (!env.RATE) {
      return text(500, "store");
    }
    const now = new Date();
    const day = now.toISOString().slice(0, 10);
    let allowed;
    try {
      allowed = await underLimit(env, day, ip);
    } catch {
      return text(500, "store");
    }
    if (!allowed) {
      return text(429, "rate");
    }
    const cf = request.cf || {};
    const asn = cleanASN(cf.asn);
    const id = crypto.randomUUID();
    const key = day + "/" + asn + "/" + id + ".json";
    const stored = {
      schema: body.schema,
      v: body.v,
      os: body.os,
      dur_s: body.dur_s,
      vpn: body.vpn,
      bypass_on: body.bypass_on,
      targets: body.targets,
      domains: body.domains,
      net: body.net,
      dns: body.dns,
      tls: body.tls,
      sni_bypass: body.sni_bypass,
      quic: body.quic,
      tcp16: body.tcp16,
      tg: body.tg,
      received: now.toISOString(),
      country: cf.country || "",
      cf_asn: cf.asn || 0,
    };
    const textBody = JSON.stringify(stored);
    try {
      if (env.REPORTS) {
        await env.REPORTS.put(key, textBody);
      } else {
        await env.RATE.put("rep:" + key, textBody, { expirationTtl: 90 * 86400 });
      }
    } catch {
      return text(500, "store");
    }
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  },
};

function text(status, msg) {
  return new Response(msg, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

function badTypes(body) {
  return typeof body.v !== "string"
    || typeof body.os !== "string"
    || typeof body.dur_s !== "number"
    || typeof body.vpn !== "boolean"
    || typeof body.bypass_on !== "boolean"
    || typeof body.targets !== "number"
    || typeof body.domains !== "number";
}

function netHasAddr(net) {
  if (!net || typeof net !== "object") {
    return false;
  }
  for (const k of Object.keys(net)) {
    const n = k.toLowerCase();
    if (n === "ip" || n === "prefix") {
      return true;
    }
  }
  return false;
}

function hasMapped(v) {
  if (!v || typeof v !== "object") {
    return false;
  }
  for (const k of Object.keys(v)) {
    const n = k.toLowerCase().replace(/-/g, "");
    if (n === "mapped" || n === "mappedaddr" || MAPPED.has(k.toLowerCase())) {
      return true;
    }
    if (hasMapped(v[k])) {
      return true;
    }
  }
  return false;
}

function cleanASN(v) {
  const d = String(v == null ? "" : v).replace(/\D/g, "");
  return d || "0";
}

async function gunzipLimited(bytes, max) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
  const reader = stream.getReader();
  const chunks = [];
  let n = 0;
  while (true) {
    const step = await reader.read();
    if (step.done) {
      break;
    }
    n += step.value.byteLength;
    if (n > max) {
      await reader.cancel();
      throw new Error("large");
    }
    chunks.push(step.value);
  }
  const out = new Uint8Array(n);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.byteLength;
  }
  return out;
}

async function underLimit(env, day, ip) {
  const saltKey = "salt:" + day;
  let salt = await env.RATE.get(saltKey);
  if (!salt) {
    const buf = new Uint8Array(16);
    crypto.getRandomValues(buf);
    salt = [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
    await env.RATE.put(saltKey, salt, { expirationTtl: 172800 });
  }
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(salt + "\n" + ip),
  );
  const hash = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  const rlKey = "rl:" + day + ":" + hash;
  const n = parseInt((await env.RATE.get(rlKey)) || "0", 10) || 0;
  if (n >= 10) {
    return false;
  }
  await env.RATE.put(rlKey, String(n + 1), { expirationTtl: 172800 });
  return true;
}
