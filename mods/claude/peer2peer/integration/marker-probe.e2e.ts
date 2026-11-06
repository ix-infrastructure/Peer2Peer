// Copyright 2026 Ix Infrastructure Inc.
//
// The mod's marker probe (MARKER_PROBE) under the real node (#49 review, H2): for each path, the
// marker of the repository, bare repository or .p2p-private folder it is in, which the mod binds
// too so a shared folder above never covers that repository once its files are gone; and which
// paths exist (a program word naming a real file, H1).

import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { MARKER_PROBE, parseMarkerProbe } from '../hooks/lib'

declare const describe: (name: string, fn: () => void) => void
declare const it: (name: string, fn: () => Promise<void> | void) => void
declare const afterAll: (fn: () => void) => void
declare const expect: (value: unknown) => any

const probe = (...paths: string[]) => parseMarkerProbe(execFileSync(process.execPath, ['-e', MARKER_PROBE, ...paths], { encoding: 'utf8', timeout: 10_000 }))

describe('the marker probe', () => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), 'p2p-marker-')))
  afterAll(() => rmSync(base, { recursive: true, force: true }))

  it('finds a working tree\'s .git, a bare repository and a .p2p-private above each path, and which paths exist', () => {
    const clone = join(base, 'src', 'team', 'tmp')
    mkdirSync(join(clone, '.git'), { recursive: true })
    writeFileSync(join(clone, 'secret.txt'), 'k')
    const quiet = join(base, 'src', 'quiet')
    mkdirSync(join(quiet, 'x'), { recursive: true })
    writeFileSync(join(quiet, '.p2p-private'), '')
    const bare = join(base, 'src', 'b.git')
    mkdirSync(join(bare, 'objects'), { recursive: true })
    mkdirSync(join(bare, 'refs'), { recursive: true })
    writeFileSync(join(bare, 'HEAD'), 'ref: refs/heads/main\n')
    const r = probe(join(clone, 'secret.txt'), join(quiet, 'x', 'not-yet.ts'), join(bare, 'objects'), join(base, 'src', 'plain'))
    expect(r?.exists).toEqual([join(clone, 'secret.txt'), join(bare, 'objects')])
    expect(r?.markers).toEqual([join(clone, '.git'), join(quiet, '.p2p-private'), join(bare, '.git')])
  })

  it('names nothing outside any repository, and skips a relative path', () => {
    mkdirSync(join(base, 'plain', 'a'), { recursive: true })
    expect(probe(join(base, 'plain', 'a'), 'relative/x')).toEqual({ exists: [join(base, 'plain', 'a')], markers: [] })
  })
})
