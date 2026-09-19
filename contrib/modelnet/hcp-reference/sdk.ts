// Workflow sketch, not production OAuth or a complete generated SDK.
export type AtomString = string;
export type HcpTransport = (method: string, path: string,
  body?: unknown, headers?: Record<string,string>) => Promise<unknown>;
export class HostedClient {
  constructor(private readonly transport: HcpTransport) {}
  search(query: string, limit = 20): Promise<unknown> {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error('invalid limit');
    return this.transport('POST', '/capabilities/search', {query, limit});
  }
  submit(intentId: string, expectedBodyId: string, idempotencyKey: string): Promise<unknown> {
    if (!idempotencyKey) throw new Error('Idempotency-Key required');
    // No automatic financial retry; retrieve exact intent after ambiguous failure.
    return this.transport('POST', `/finance/intents/${encodeURIComponent(intentId)}/submit`,
      {expected_body_id: expectedBodyId}, {'Idempotency-Key': idempotencyKey});
  }
}
