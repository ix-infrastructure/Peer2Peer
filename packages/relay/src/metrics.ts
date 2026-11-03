// Copyright 2026 Ix Infrastructure Inc.
//
// Prometheus text-format metrics. Counts only: no label ever carries a
// userId, device id, capability or IP.

function labelKey(labels?: Record<string, string>): string {
  if (!labels) return "";
  return Object.entries(labels)
    .map(([k, v]) => `${k}="${v.replace(/["\\\n]/g, "_")}"`)
    .join(",");
}

export class Metrics {
  private readonly counters = new Map<string, { help: string; values: Map<string, number> }>();
  private readonly gauges = new Map<string, { help: string; read: () => number }>();

  constructor(private readonly prefix = "p2p_relay_") {}

  counter(name: string, help: string): void {
    if (!this.counters.has(name)) this.counters.set(name, { help, values: new Map() });
  }

  gauge(name: string, help: string, read: () => number): void {
    this.gauges.set(name, { help, read });
  }

  /** Increments counter `name`. Label values must come from a small fixed set. */
  inc(name: string, labels?: Record<string, string>, by = 1): void {
    const c = this.counters.get(name);
    if (!c) throw new Error(`metrics: unknown counter ${name}`);
    const key = labelKey(labels);
    c.values.set(key, (c.values.get(key) ?? 0) + by);
  }

  /** A counter's value (summed over labels when none are given). */
  get(name: string, labels?: Record<string, string>): number {
    const c = this.counters.get(name);
    if (!c) return 0;
    if (!labels) return [...c.values.values()].reduce((a, b) => a + b, 0);
    return c.values.get(labelKey(labels)) ?? 0;
  }

  render(): string {
    const out: string[] = [];
    for (const [name, c] of this.counters) {
      const full = `${this.prefix}${name}_total`;
      out.push(`# HELP ${full} ${c.help}`, `# TYPE ${full} counter`);
      if (c.values.size === 0) out.push(`${full} 0`);
      for (const [labels, v] of c.values) out.push(labels ? `${full}{${labels}} ${v}` : `${full} ${v}`);
    }
    for (const [name, g] of this.gauges) {
      const full = `${this.prefix}${name}`;
      let v: number;
      try {
        v = g.read();
      } catch {
        v = NaN;
      }
      out.push(`# HELP ${full} ${g.help}`, `# TYPE ${full} gauge`, `${full} ${v}`);
    }
    return `${out.join("\n")}\n`;
  }
}
