export default {
  async email(message, env, ctx) {
    const raw = await streamToText(message.raw);
    const id = requestIdFromTo(message.to) ?? requestIdFromSubject(raw) ?? "";
    const res = await fetch(env.KSG_SERVICE_MAIL_URL, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "authorization": `Bearer ${env.KSG_WORKER_SECRET}`,
      },
      body: JSON.stringify({ id, raw }),
    });
    if (!res.ok) console.error(`bare-mail forward failed: ${res.status} id=${id.length}`);
  },
};

function requestIdFromTo(to) {
  const m = /verify\+([A-Za-z0-9_-]{1,64})@/i.exec(to || "");
  return m ? m[1] : null;
}

function requestIdFromSubject(raw) {
  const m = /^subject:.*\[([A-Za-z0-9_-]{1,64})\]/im.exec(raw);
  return m ? m[1] : null;
}

async function streamToText(stream) {
  const reader = stream.getReader();
  const chunks = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.length;
  }
  return new TextDecoder().decode(buf);
}
