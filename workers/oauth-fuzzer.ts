/** A queue consumer: send one authorization request, record where it actually goes. */
export interface Env {
  RESULTS: KVNamespace;
}

export interface Probe {
  client_id: string;
  authorize: string;
  params: Record<string, string>;
}

export default {
  async queue(batch: MessageBatch<Probe>, env: Env): Promise<void> {
    for (const message of batch.messages) {
      const probe = message.body;
      const url = new URL(probe.authorize);
      for (const [key, value] of Object.entries(probe.params)) url.searchParams.set(key, value);
      let outcome: Record<string, unknown>;
      try {
        const answer = await fetch(url.toString(), { redirect: "manual",
          headers: { "user-agent": "Mozilla/5.0 (compatible; agentic-offsec/0.1)" } });
        outcome = { status: answer.status, location: answer.headers.get("location") ?? null };
      } catch (error) {
        outcome = { error: error instanceof Error ? error.message : String(error) };
      }
      const record = { client_id: probe.client_id, params: probe.params, url: url.toString(),
        at: new Date().toISOString(), ...outcome };
      await env.RESULTS.put(`${record.at}:${probe.client_id}`, JSON.stringify(record),
        { expirationTtl: 60 * 60 * 24 * 30 });
      message.ack();
    }
  },
};
