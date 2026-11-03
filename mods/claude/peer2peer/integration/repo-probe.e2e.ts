// Copyright 2026 Ix Infrastructure Inc.
//
// The mod's no-git repo probe (REPO_PROBE) under the real node: it finds the
// repo a directory is in by its `.git` alone (a folder, or a linked
// worktree's `gitdir:` file), with its branch, and nothing outside a repo.

import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { parseRepoProbe, pathBasename, REPO_PROBE } from '../hooks/lib'

declare const describe: (name: string, fn: () => void) => void
declare const it: (name: string, fn: () => Promise<void> | void) => void
declare const afterAll: (fn: () => void) => void
declare const expect: (value: unknown) => any

const probe = (dir: string, env: Record<string, string> = {}) =>
  parseRepoProbe(execFileSync(process.execPath, ['-e', REPO_PROBE, dir], { encoding: 'utf8', timeout: 10_000, env: { ...process.env, ...env } }))

describe('the no-git repo probe', () => {
  const base = mkdtempSync(join(tmpdir(), 'p2p-probe-'))
  afterAll(() => rmSync(base, { recursive: true, force: true }))

  it('finds the repo root and branch from a subdirectory', () => {
    const repo = join(base, 'Sandbox')
    mkdirSync(join(repo, '.git'), { recursive: true })
    writeFileSync(join(repo, '.git', 'HEAD'), 'ref: refs/heads/feat/login\n')
    mkdirSync(join(repo, 'src', 'app'), { recursive: true })
    const r = probe(join(repo, 'src', 'app'))
    expect(r.root).toBe(repo)
    expect(r.branch).toBe('feat/login')
    expect(pathBasename(r.root ?? '')).toBe('Sandbox')
  })

  it('follows a linked worktree\'s gitdir file', () => {
    const gd = join(base, 'Sandbox', '.git', 'worktrees', 'wt1')
    mkdirSync(gd, { recursive: true })
    writeFileSync(join(gd, 'HEAD'), 'ref: refs/heads/wt-branch\n')
    const wt = join(base, 'wt1')
    mkdirSync(wt)
    writeFileSync(join(wt, '.git'), `gitdir: ${gd}\n`)
    // Without the main repo's link back to this worktree, the gitdir isn't trusted: no branch.
    expect(probe(wt)).toEqual({ root: wt })
    writeFileSync(join(gd, 'gitdir'), `${join(wt, '.git')}\n`)
    expect(probe(wt)).toEqual({ root: wt, branch: 'wt-branch' })
  })

  it('a detached HEAD has no branch; outside any repo there is nothing', () => {
    const repo = join(base, 'detached')
    mkdirSync(join(repo, '.git'), { recursive: true })
    writeFileSync(join(repo, '.git', 'HEAD'), '0123456789abcdef0123456789abcdef01234567\n')
    expect(probe(repo)).toEqual({ root: repo })
    const outside = mkdtempSync(join(tmpdir(), 'p2p-probe-none-'))
    try {
      // tmpdir itself may sit in a repo on a developer's machine; only check that what is found is an ancestor.
      const r = probe(outside)
      if (r.root) expect(outside.startsWith(r.root)).toBe(true)
    } finally {
      rmSync(outside, { recursive: true, force: true })
    }
  })

  it('review M4: a gitdir outside a .git/worktrees dir, a branch with .., or a non-regular HEAD gives no branch, and never hangs', () => {
    const evil = join(base, 'evil-gitdir')
    mkdirSync(join(base, 'elsewhere'), { recursive: true })
    writeFileSync(join(base, 'elsewhere', 'HEAD'), 'ref: refs/heads/stolen\n')
    mkdirSync(evil)
    writeFileSync(join(evil, '.git'), `gitdir: ${join(base, 'elsewhere')}\n`)
    expect(probe(evil)).toEqual({ root: evil })

    const dots = join(base, 'dots')
    mkdirSync(join(dots, '.git'), { recursive: true })
    writeFileSync(join(dots, '.git', 'HEAD'), 'ref: refs/heads/../../etc\n')
    expect(probe(dots)).toEqual({ root: dots })

    if (process.platform !== 'win32') {
      const fifo = join(base, 'fifo')
      mkdirSync(join(fifo, '.git'), { recursive: true })
      execFileSync('mkfifo', [join(fifo, '.git', 'HEAD')])
      expect(probe(fifo)).toEqual({ root: fifo })

      const linked = join(base, 'linked-head')
      mkdirSync(join(linked, '.git'), { recursive: true })
      symlinkSync('/dev/zero', join(linked, '.git', 'HEAD'))
      expect(probe(linked)).toEqual({ root: linked })

      // A symlinked .git is no repo marker, and the walk stops there (review L-b): not even a
      // real repo above it counts.
      const outer = join(base, 'outer')
      mkdirSync(join(outer, '.git'), { recursive: true })
      writeFileSync(join(outer, '.git', 'HEAD'), 'ref: refs/heads/main\n')
      const symgit = join(outer, 'symgit')
      mkdirSync(symgit)
      symlinkSync(join(base, 'Sandbox', '.git'), join(symgit, '.git'))
      expect(probe(symgit)).toEqual({})
      expect(probe(join(outer))).toEqual({ root: outer, branch: 'main' })
    }
  })

  it('review M4: the walk stops at home and never takes an ancestor of home', () => {
    const top = join(base, 'top')
    const home = join(top, 'home', 'sam')
    const work = join(home, 'work', 'proj')
    mkdirSync(work, { recursive: true })
    // A .git above home (an ancestor of it) is refused.
    mkdirSync(join(top, '.git'), { recursive: true })
    writeFileSync(join(top, '.git', 'HEAD'), 'ref: refs/heads/main\n')
    expect(probe(work, { HOME: home, USERPROFILE: home })).toEqual({})
    // One at home itself still counts (the walk stops there).
    mkdirSync(join(home, '.git'))
    writeFileSync(join(home, '.git', 'HEAD'), 'ref: refs/heads/dotfiles\n')
    expect(probe(work, { HOME: home, USERPROFILE: home })).toEqual({ root: home, branch: 'dotfiles' })
  })
})
