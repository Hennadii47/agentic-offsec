/** What an access is worth, from the same price book the Python side reads. */
export interface Env {
  PRICING: KVNamespace;
}

const FALLBACK: Record<string, number> = {
  cloud_admin: 50000, k8s_cluster_admin: 20000, ci_cd_secrets: 8000,
  bank_oauth_token: 12000, gov_oauth_token: 15000, ide_publisher_account: 5000,
  ssh_key: 3000, generic_api_key: 500,
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const kind = new URL(request.url).searchParams.get("kind") ?? "generic_api_key";
    const stored = await env.PRICING.get("initial_access");
    const book = stored ? (JSON.parse(stored) as Record<string, number>) : FALLBACK;
    const usd = book[kind] ?? book.generic_api_key ?? 0;
    return new Response(JSON.stringify({ kind, usd, source: stored ? "kv" : "fallback" }),
      { headers: { "content-type": "application/json" } });
  },
};
