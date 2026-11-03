// Copyright 2026 Ix Infrastructure Inc.
//
// The simulated link the latency bench (latency.mjs) and the soak harness
// (scripts/soak) put between a client and a local relay: a TCP proxy on
// 127.0.0.1 that holds each chunk for RTT/2 in each direction, including the
// TCP handshake, so the same run gives loopback numbers and numbers for a
// simulated link.
//
// Optional jitter adds a random 0..jitterMs to each chunk's delay, but never
// reorders a direction's bytes: a chunk leaves no earlier than the one before
// it (TCP is a stream). `dropAll()` destroys every open connection at once (a
// Wi-Fi drop), and `pause()` / `resume()` refuse new connections and drop open
// ones while paused (a dead link). Nothing here talks to anything but the
// target port on 127.0.0.1.

import net from "node:net";

/**
 * @param {number} targetPort the relay's port on 127.0.0.1
 * @param {{ oneWayMs?: number, jitterMs?: number, random?: () => number, port?: number }} [opts]
 */
export function startProxy(targetPort, opts = {}) {
  const state = { oneWayMs: opts.oneWayMs ?? 0, jitterMs: opts.jitterMs ?? 0, down: false, targetPort };
  const random = opts.random ?? Math.random;
  const sockets = new Set();
  const delay = () => state.oneWayMs + (state.jitterMs > 0 ? random() * state.jitterMs : 0);
  const server = net.createServer((client) => {
    if (state.down) {
      client.destroy();
      return;
    }
    client.setNoDelay(true);
    const upstream = net.connect(state.targetPort, "127.0.0.1");
    upstream.setNoDelay(true);
    sockets.add(client);
    sockets.add(upstream);
    const forget = (s) => s.on("close", () => sockets.delete(s));
    forget(client);
    forget(upstream);
    const pipe = (from, to) => {
      // FIFO per direction: a chunk never overtakes the one before it. One queue and one timer per
      // direction (separate timers that expire in the same millisecond may fire in any order).
      let lastAt = 0;
      const queue = [];
      let timer;
      const pump = () => {
        timer = undefined;
        const now = Date.now();
        while (queue.length > 0 && queue[0].at <= now) {
          const x = queue.shift();
          if (x.end) to.end();
          else if (x.destroy) to.destroy();
          else if (to.writable) to.write(x.d);
        }
        if (queue.length > 0) timer = setTimeout(pump, queue[0].at - now);
      };
      // Data, then the end and the close, in order, each after the one-way delay.
      const enqueue = (x, ms) => {
        const at = Math.max(Date.now() + ms, lastAt);
        lastAt = at;
        queue.push({ at, ...x });
        if (timer === undefined) timer = setTimeout(pump, Math.max(0, queue[0].at - Date.now()));
      };
      from.on("data", (d) => {
        const ms = delay();
        if (ms <= 0 && queue.length === 0) to.write(d);
        else enqueue({ d }, ms);
      });
      from.on("end", () => enqueue({ end: true }, state.oneWayMs));
      from.on("error", () => to.destroy());
      from.on("close", () => enqueue({ destroy: true }, state.oneWayMs + 5));
    };
    // The TCP handshake itself costs one RTT on a real link.
    const go = () => {
      pipe(client, upstream);
      pipe(upstream, client);
    };
    client.pause();
    upstream.once("connect", () => setTimeout(() => (client.resume(), go()), 2 * state.oneWayMs));
    upstream.on("error", () => client.destroy());
    client.on("error", () => upstream.destroy());
  });
  const dropAll = () => {
    for (const s of sockets) s.destroy();
    sockets.clear();
  };
  return new Promise((r) =>
    server.listen(opts.port ?? 0, "127.0.0.1", () =>
      r({
        port: server.address().port,
        state,
        /** Open client and upstream sockets (two per proxied connection). */
        open: () => sockets.size,
        dropAll,
        pause: () => {
          state.down = true;
          dropAll();
        },
        resume: () => {
          state.down = false;
        },
        close: () =>
          new Promise((c) => {
            dropAll();
            server.close(() => c());
          }),
      }),
    ),
  );
}
