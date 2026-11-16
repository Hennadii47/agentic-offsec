/** The beacon a canary package calls home to: a hit is a build that resolved us. */
export interface Env {
  HITS: KVNamespace;
  CANARY_SECRET: string;
}

async function verify(name: string, version: string, signature: string, secret: string): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${name}@${version}`));
  const hex = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
  if (hex.length !== signature.length) return false;
  let diff = 0;
  for (let i = 0; i < hex.length; i += 1) diff |= hex.charCodeAt(i) ^ signature.charCodeAt(i);
  return diff === 0;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const name = url.searchParams.get("pkg") ?? "";
    const version = url.searchParams.get("v") ?? "";
    const signature = url.searchParams.get("sig") ?? "";
    if (!name || !version || !signature) {
      return new Response(JSON.stringify({ error: "pkg, v and sig are required" }), { status: 400 });
    }
    if (!(await verify(name, version, signature, env.CANARY_SECRET))) {
      return new Response(JSON.stringify({ error: "signature does not match" }), { status: 403 });
    }
    const hit = { name, version, at: new Date().toISOString(),
      country: request.cf?.country ?? null, asn: request.cf?.asn ?? null,
      ua: request.headers.get("user-agent") ?? "" };
    await env.HITS.put(`${hit.at}:${name}`, JSON.stringify(hit), { expirationTtl: 60 * 60 * 24 * 180 });
    return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
  },
};
