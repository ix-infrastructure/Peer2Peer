#!/usr/bin/env node
// Copyright 2026 Ix Infrastructure Inc.
//
// The soak harness's library-level steps, run against the home in P2P_HOME
// (the environment the harness builds for a device). These are the things the
// CLI can't script, or on purpose won't do:
//
//   link-start <out-file> <label>   on a key-holding device: open a link and write
//                                   the code to <out-file>; confirm the device
//                                   whose label and compare code match the
//                                   answer file (<out-file>.answer)
//   link-join <code-file> <label>   on the new device: join with the code, write
//                                   the compare code to <code-file>.answer
//   malformed <userId> <sid>        send <userId> envelopes a conforming client
//                                   never sends: a status whose state is not
//                                   busy|idle, and a message whose text is a number
//   flood <userId> <did> <sid> <n> <prefix>
//                                   n messages into <userId>'s session <sid>, to
//                                   device <did> only (fills that mailbox)
//
// It prints one JSON line. It uses packages/p2p/dist (built), never the caller's home.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const dist = join(repo, "packages/p2p/dist");
const cli = await import(pathToFileURL(join(dist, "index.js")).href);
const identity = await import(pathToFileURL(join(dist, "identity.js")).href);

const errs = [];
const io = { out: () => {}, err: (s) => errs.push(String(s)) };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const done = (v, code = 0) => {
  process.stdout.write(JSON.stringify(v) + "\n");
  process.exit(code);
};

const [cmd, ...args] = process.argv.slice(2);
const app = new cli.App({ env: { ...process.env }, io });

try {
  if (cmd === "link-start") {
    const [outFile, label] = args;
    await app.load();
    cli.receiving(app);
    const s = await identity.linkStart(app, {});
    writeFileSync(outFile, s.code);
    const r = await s.wait(async (req) => {
      // The new device writes its compare code next to the link code (a channel we control).
      const ans = `${outFile}.answer`;
      for (let i = 0; i < 200 && !existsSync(ans); i++) await sleep(100);
      return existsSync(ans) && readFileSync(ans, "utf8").trim() === req.compareCode && req.label === label;
    });
    await app.close();
    done({ ok: true, did: r.did, ver: r.ver });
  } else if (cmd === "link-join") {
    const [codeFile, label] = args;
    for (let i = 0; i < 300 && !existsSync(codeFile); i++) await sleep(100);
    const code = readFileSync(codeFile, "utf8").trim();
    const j = await identity.linkJoin(app, code, { label });
    writeFileSync(`${codeFile}.answer`, j.compareCode);
    const r = await j.wait();
    await app.close();
    done({ ok: true, did: r.did, userId: r.userId });
  } else if (cmd === "malformed") {
    const [to, sid] = args;
    await app.load();
    cli.receiving(app);
    await app.connectAndDrain();
    const session = { own: app.userId, sid };
    const sessDoc = (await app.state.get("sessions"))?.[sid];
    const a = await app.deliver(to, "status", session, { status: { state: "exploding", label: "soak-malformed" }, ...(sessDoc ? { roster: sessDoc.jws } : {}) });
    const b = await app.deliver(to, "msg", session, { text: 42, ...(sessDoc ? { roster: sessDoc.jws } : {}) });
    await app.close();
    done({ ok: true, status: a.relays.length, msg: b.relays.length });
  } else if (cmd === "flood") {
    const [to, did, sid, n, prefix] = args;
    await app.load();
    cli.receiving(app);
    await app.connectAndDrain();
    const target = { own: to, sid };
    const roster = (await app.store.getRoster(to, sid))?.jws;
    const sent = [];
    for (let i = 0; i < Number(n); i++) {
      const text = `${prefix}-${i}`;
      const d = await app.deliver(to, "msg", target, { text, ...(roster ? { roster } : {}) }, { onlyDevices: [did] });
      if (d.relays.length > 0) sent.push({ text, relays: d.relays.length });
    }
    await app.close();
    done({ ok: true, sent });
  } else {
    done({ ok: false, error: `unknown helper command ${cmd}` }, 2);
  }
} catch (e) {
  await app.close().catch(() => {});
  done({ ok: false, error: String(e?.message ?? e).slice(0, 500), errs: errs.slice(-5).map((l) => l.slice(0, 300)) }, 1);
}
