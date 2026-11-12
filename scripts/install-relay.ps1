# Copyright 2026 Ix Infrastructure Inc.
# SPDX-License-Identifier: Apache-2.0
#
# install-relay.ps1: install a private Peer2Peer relay on Windows 10/11 or
# Windows Server. PowerShell 5.1 or newer.
#
#   .\install-relay.ps1 -Url wss://relay.example.org/v3        # from a checkout or a download
#   & ([scriptblock]::Create((irm https://ix-infra.com/p2p/install-relay.ps1))) -Url wss://relay.example.org/v3
#   $env:P2P_RELAY_URL = 'wss://relay.example.org/v3'; irm https://ix-infra.com/p2p/install-relay.ps1 | iex
#
# With `| iex` there are no parameters: set P2P_RELAY_URL, P2P_RELAY_PRESET,
# P2P_RELAY_DATA_DIR or P2P_RELAY_DRY_RUN=1 first, or use the scriptblock form.
#
# What it does (docs/run-a-relay-on-any-machine.md has the whole guide):
#   1. Detects Docker Desktop (and whether it runs Linux containers on WSL2),
#      Node, the CPU type and the RAM.
#   2. Docker with Linux containers: builds the relay image and runs it
#      hardened, with a memory cap, a restart policy, a named volume (or
#      -DataDir) and the `small` preset under 4 GB of RAM.
#   3. Otherwise Node >= 22.13: builds the relay as you, then, elevated, copies
#      it into %ProgramData%\p2p-relay and registers a Scheduled Task that
#      starts it at boot as a dedicated low-privilege local account.
#   4. Otherwise: prints what's missing and your options.
#   It listens on 127.0.0.1 only, unless -OpenFirewall is given.
#
# Parameters: -Url, -Port, -Preset small|default, -DataDir, -Method
# auto|docker|node, -Replace, -OpenFirewall, -DryRun, and -RelayEnv @{ NAME =
# 'value' } for other relay settings (for example RELAY_ALLOW_CIRCLE).
#
# Why a Scheduled Task and a dedicated account: Windows services must speak
# the service control protocol, which node.exe doesn't, so running Node as a
# service needs a third-party wrapper (NSSM, WinSW). A Scheduled Task with an
# "at startup" trigger needs nothing extra. It runs as a local account made
# for the relay, a member of no group, whose random password is generated
# inside the elevated step, handed only to Task Scheduler, and never shown or
# saved. LocalSystem would give the relay the whole machine; LocalService is
# shared by many Windows services, so data it can write, they can too. The
# install folder is readable (not writable) by that account; only its data
# folder is writable.
#
# Elevation is requested once, for that step and for -OpenFirewall, and the
# script says so first. The Docker path needs none.
#
# Safe to pipe: everything is inside Install-P2PRelay, called on the last line,
# so a truncated download runs nothing. It never relies on its own path.
# Outside a checkout it downloads the relay source for $RelayVersion and checks
# its SHA-256 before using it.
#
# Detection can be overridden for testing: P2P_DETECT_OS (Windows),
# P2P_DETECT_ARCH, P2P_DETECT_MEM_MB, P2P_DETECT_DOCKER, P2P_DETECT_DOCKER_OSTYPE,
# P2P_DETECT_DOCKER_KERNEL, P2P_DETECT_NODE, P2P_NODE_BIN, P2P_SOURCE_DIR. Set a
# P2P_DETECT_* variable to "none" for "not found".

[CmdletBinding()]
param(
    [switch]$DryRun,
    [string]$Url = '',
    [ValidateRange(1, 65535)][int]$Port = 8080,
    [ValidateSet('', 'small', 'default')][string]$Preset = '',
    [string]$DataDir = '',
    [ValidateSet('auto', 'docker', 'node')][string]$Method = 'auto',
    [switch]$OpenFirewall,
    [switch]$Replace,
    [hashtable]$RelayEnv = @{}
)

function Install-P2PRelay {
    [CmdletBinding()]
    param(
        [switch]$DryRun,
        [string]$Url = '',
        [ValidateRange(1, 65535)][int]$Port = 8080,
        [ValidateSet('', 'small', 'default')][string]$Preset = '',
        [string]$DataDir = '',
        [ValidateSet('auto', 'docker', 'node')][string]$Method = 'auto',
        [switch]$OpenFirewall,
        [switch]$Replace,
        [hashtable]$RelayEnv = @{}
    )
    Set-StrictMode -Version 2.0
    $ErrorActionPreference = 'Stop'

    # Pinned from the release's SHA256SUMS asset (docs/releasing.md, step 5).
    # GitHub's generated /archive/ tarballs aren't byte-stable, so they are
    # never used.
    # TODO: once releases publish a multi-arch image
    # (for example on GHCR), pull it by digest instead of building locally.
    $RelayVersion = '0.1.1'
    $RelaySourceSha256 = '9f0c72e30f62c0abcb608b09c5ebdc75a27ce9e725a11f5540db65e5842c709f'
    $RelaySourceUrlBase = 'https://github.com/ix-infrastructure/Peer2Peer/releases/download'

    $image = 'peer2peer/relay:local'
    $name = 'p2p-relay'
    $minDocker = [version]'20.10.10'
    $minNode = [version]'22.13.0'

    function Write-Say([string]$Message) { Write-Information -MessageData $Message -InformationAction Continue }

    # Runs a native command, printing it first; does nothing in a dry run.
    function Invoke-Step([string]$Exe, [string[]]$Arguments) {
        $shown = ($Arguments | ForEach-Object { if ($_ -match '[\s"]') { "'" + $_ + "'" } else { $_ } }) -join ' '
        Write-Say "+ $Exe $shown"
        if ($DryRun) { return }
        & $Exe @Arguments
        if ($LASTEXITCODE -ne 0) { throw "$Exe failed with exit code $LASTEXITCODE" }
    }

    function Get-Detected([string]$Var, [scriptblock]$Probe) {
        $v = [Environment]::GetEnvironmentVariable($Var)
        if ($null -ne $v -and $v -ne '') { if ($v -eq 'none') { return '' } else { return $v } }
        try { return [string](& $Probe) } catch { return '' }
    }

    function ConvertTo-Version([string]$Text) {
        $m = [regex]::Match($Text, '^\D*(\d+)\.(\d+)\.(\d+)')
        if (-not $m.Success) { return $null }
        return [version]("{0}.{1}.{2}" -f $m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value)
    }

    # A Windows folder path of plain characters (it reaches a .cmd file and docker arguments),
    # never a drive root, a profile or a system folder.
    function Test-DataDirPath([string]$Path) {
        if ($Path -cnotmatch '\A[A-Za-z]:\\[A-Za-z0-9_.\\ -]+\z') {
            throw "-DataDir must be a full path such as D:\p2p-relay\data, of letters, digits, spaces and _ . - only (got '$Path')"
        }
        if ($Path -match '\\\\|\\\.{1,2}(\\|\z)') { throw "-DataDir must not contain empty, . or .. parts (got '$Path')" }
        $p = $Path.TrimEnd('\')
        if ($p -match '\A[A-Za-z]:\z') { throw '-DataDir must not be a drive root' }
        $under = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432, "$env:ProgramData\Microsoft",
            'C:\Windows', 'C:\Program Files', 'C:\Program Files (x86)', 'C:\Users', $env:USERPROFILE) | Where-Object { $_ }
        foreach ($d in $under) {
            if ($p -ieq $d -or $p.StartsWith("$d\", [StringComparison]::OrdinalIgnoreCase)) { throw "-DataDir $Path is a system or profile folder; use a folder of its own, such as D:\p2p-relay\data" }
        }
        if ($env:ProgramData -and $p -ieq $env:ProgramData) { throw '-DataDir must not be ProgramData itself' }
    }

    # Folder-safety helpers, shared word for word by this (unelevated) script and the elevated
    # step, which gets the same text. Pure string and ACL logic; tests load this region alone.
    $rightsLib = @'
# region rights
# The parent of a Windows path (C:\a\b -> C:\a, C:\a -> C:\, C:\ -> ''), the same on every platform.
function Get-WindowsParent([string]$Path) {
    $t = $Path.TrimEnd('\')
    $i = $t.LastIndexOf('\')
    if ($i -lt 0) { return '' }
    if ($i -eq 2) { return $t.Substring(0, 3) }
    return $t.Substring(0, $i)
}
# Every folder from the drive root down to PATH itself: C:\a\b -> C:\, C:\a, C:\a\b.
function Get-WindowsChain([string]$Path) {
    $chain = @()
    $p = $Path.TrimEnd('\')
    if ($p -match '\A[A-Za-z]:\z') { $p = "$p\" }
    while ($p) {
        $chain = @($p) + $chain
        $up = Get-WindowsParent $p
        if ($up -eq $p) { break }
        $p = $up
    }
    return $chain
}
# Generic rights in an ACE (GENERIC_ALL, GENERIC_WRITE, ...) mapped to the file rights they mean.
function ConvertTo-SpecificRights([long]$Rights) {
    $r = $Rights
    if ($r -lt 0) { $r += 4294967296 }
    if ($r -band 268435456) { $r = $r -bor 2032127 }        # GENERIC_ALL -> FILE_ALL_ACCESS
    if ($r -band 1073741824) { $r = $r -bor 1179926 }       # GENERIC_WRITE -> FILE_GENERIC_WRITE
    if ($r -band 2147483648) { $r = $r -bor 1179785 }       # GENERIC_READ -> FILE_GENERIC_READ
    if ($r -band 536870912) { $r = $r -bor 1179808 }        # GENERIC_EXECUTE -> FILE_GENERIC_EXECUTE
    return $r
}
# Rights that let a holder remove, rename or re-permission a folder or what is inside it:
# DELETE, WRITE_DAC, WRITE_OWNER, FILE_DELETE_CHILD. (Creating new entries isn't enough to
# replace one that exists; folders that don't exist yet are created by the elevated step,
# one at a time, each checked for its owner.)
function Test-RightsLetSwap([long]$Rights) {
    return [bool]((ConvertTo-SpecificRights $Rights) -band (65536 -bor 262144 -bor 524288 -bor 64))
}
# Can any of SIDS swap or re-permission PATH or what is under it? Owning it is enough.
function Test-SidsCanSwap([string]$Path, [string[]]$Sids) {
    $acl = Get-Acl -LiteralPath $Path
    if ($Sids -contains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { return $true }
    foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if ($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        if (($Sids -contains $ace.IdentityReference.Value) -and (Test-RightsLetSwap ([long][int]$ace.FileSystemRights))) { return $true }
    }
    return $false
}
# The first existing folder, from the drive root down to DIR's parent, that SIDS could swap.
function Get-SwappableAncestor([string]$Dir, [string[]]$Sids) {
    # Test hook, never honoured in the elevated step (which sets $P2PElevated).
    if ($env:P2P_DETECT_SWAPPABLE -and -not (Get-Variable -Name P2PElevated -ValueOnly -ErrorAction SilentlyContinue)) {
        foreach ($c in (Get-WindowsChain (Get-WindowsParent $Dir))) { if (@($env:P2P_DETECT_SWAPPABLE -split ';') -contains $c) { return $c } }
        return ''
    }
    foreach ($c in (Get-WindowsChain (Get-WindowsParent $Dir))) {
        if (-not (Test-Path -LiteralPath $c)) { break }
        if (Test-SidsCanSwap $c $Sids) { return $c }
    }
    return ''
}
# The SIDs of the user running the install, from this process's own token, leaving out
# Administrators, SYSTEM and "local account and member of Administrators", plus Everyone,
# Authenticated Users and Users, which every signed-in user has. The elevated step calls this
# itself (same account, elevated token) and never takes the list, or the test hook, from the
# unelevated side.
function Get-UserSid {
    $elevatedStep = Get-Variable -Name P2PElevated -ValueOnly -ErrorAction SilentlyContinue
    if ($env:P2P_DETECT_USER_SIDS -and -not $elevatedStep) { return @($env:P2P_DETECT_USER_SIDS -split ';') }
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $privileged = @('S-1-5-32-544', 'S-1-5-18', 'S-1-5-114')
    $all = @($id.User.Value) + @($id.Groups | ForEach-Object { $_.Value }) + @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')
    return @($all | Where-Object { $privileged -notcontains $_ } | Select-Object -Unique)
}
# A new folder that is born locked: owned by Administrators, no inherited permissions, only
# Administrators and SYSTEM allowed, all in the one create call, so there is no moment with
# the parent's (possibly user-writable) inherited permissions before icacls runs.
function New-LockedDirectory([string]$Path) {
    $sec = New-Object Security.AccessControl.DirectorySecurity
    $sec.SetAccessRuleProtection($true, $false)
    $sec.SetOwner((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'))
    foreach ($sid in 'S-1-5-32-544', 'S-1-5-18') {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier $sid), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        $sec.AddAccessRule($rule)
    }
    # Windows PowerShell 5.1 (.NET Framework) has Directory.CreateDirectory(path, security);
    # PowerShell 7 (.NET) has FileSystemAclExtensions.Create(DirectoryInfo, security).
    $withAcl = [IO.Directory].GetMethod('CreateDirectory', [type[]]@([string], [Security.AccessControl.DirectorySecurity]))
    if ($withAcl) { [void]$withAcl.Invoke($null, @($Path, $sec)) }
    else { [IO.FileSystemAclExtensions]::Create((New-Object IO.DirectoryInfo $Path), $sec) }
}
# endregion rights
'@
    . ([scriptblock]::Create($rightsLib))

    # The SIDs of the user running this, leaving out Administrators and SYSTEM.
    # new, empty, owned or foreign. -AdminOnly (the Node path, whose folders Administrators
    # change): a folder counts as the relay's only when Administrators, SYSTEM or the relay's
    # account own it, so a marker someone else planted means nothing.
    function Get-DirState([string]$Path, [string]$OverrideVar = 'P2P_DETECT_DATADIR_STATE', [switch]$AdminOnly) {
        $o = [Environment]::GetEnvironmentVariable($OverrideVar)
        if ($o) { return $o }
        if (-not (Test-Path -LiteralPath $Path)) { return 'new' }
        $item = Get-Item -LiteralPath $Path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return 'foreign' }
        $acl = Get-Acl -LiteralPath $Path
        $empty = -not (Get-ChildItem -LiteralPath $Path -Force | Select-Object -First 1)
        if ($acl.Owner -match '\\p2p-relay\z') { return 'owned' }
        $marked = Test-Path -LiteralPath (Join-Path $Path '.p2p-relay')
        if ($AdminOnly) {
            $admin = @('S-1-5-32-544', 'S-1-5-18') -contains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
            if ($admin -and $marked) { return 'owned' }
            if ($empty) { return 'empty' }
            return 'foreign'
        }
        if ($marked) { return 'owned' }
        if ($empty) { return 'empty' }
        return 'foreign'
    }

    # Is DIR clearly a checkout of this repository (not just any folder with a packages\relay)?
    function Test-Checkout([string]$Dir) {
        $pkg = Join-Path $Dir 'packages/relay/package.json'
        return (Test-Path (Join-Path $Dir '.git')) -and (Test-Path (Join-Path $Dir 'scripts/install-relay.ps1')) -and
            (Test-Path $pkg) -and ((Get-Content -Raw $pkg) -match '"name": "@peer2peer/relay"')
    }

    function Get-RelaySource {
        if ($env:P2P_SOURCE_DIR) { Write-Say "building from P2P_SOURCE_DIR=$env:P2P_SOURCE_DIR"; return $env:P2P_SOURCE_DIR }
        $here = (Get-Location).Path
        if (Test-Checkout $here) { Write-Say "building from the checkout in $here"; return $here }
        if (-not $RelayVersion -or -not $RelaySourceSha256) {
            throw 'No Peer2Peer release is pinned in this script yet: run it from the root of a checkout (git clone https://github.com/ix-infrastructure/Peer2Peer, cd Peer2Peer, .\scripts\install-relay.ps1 ...).'
        }
        $src = "$RelaySourceUrlBase/v$RelayVersion/peer2peer-$RelayVersion-src.tar.gz"
        if ($DryRun) { Write-Say "+ download $src, check SHA-256 $RelaySourceSha256, unpack"; return '<download>' }
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('p2p-relay-src-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tmp | Out-Null
        $tgz = Join-Path $tmp 'src.tar.gz'
        Write-Say "downloading $src"
        Invoke-WebRequest -Uri $src -OutFile $tgz -UseBasicParsing
        $got = (Get-FileHash -Algorithm SHA256 -Path $tgz).Hash.ToLowerInvariant()
        if ($got -ne $RelaySourceSha256.ToLowerInvariant()) {
            throw "Checksum mismatch for ${src}: got $got, expected $RelaySourceSha256. Nothing was installed."
        }
        $out = Join-Path $tmp 'src'
        New-Item -ItemType Directory -Path $out | Out-Null
        & tar.exe -xzf $tgz -C $out --strip-components=1
        if ($LASTEXITCODE -ne 0) { throw 'could not unpack the relay source' }
        return $out
    }

    function Wait-Healthy {
        if ($DryRun) { Write-Say "+ wait for http://127.0.0.1:$Port/healthz"; return $true }
        for ($i = 0; $i -lt 30; $i++) {
            try {
                $r = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/healthz" -UseBasicParsing -TimeoutSec 2
                if ($r.StatusCode -eq 200) { return $true }
            } catch { Start-Sleep -Seconds 1 }
        }
        return $false
    }

    # ---- options -----------------------------------------------------------
    # `irm ... | iex` can't pass parameters, so these environment variables stand in for them.
    if (-not $Url -and $env:P2P_RELAY_URL) { $Url = $env:P2P_RELAY_URL }
    if (-not $Preset -and $env:P2P_RELAY_PRESET) { $Preset = $env:P2P_RELAY_PRESET }
    if (-not $DataDir -and $env:P2P_RELAY_DATA_DIR) { $DataDir = $env:P2P_RELAY_DATA_DIR }
    if (-not $DryRun -and $env:P2P_RELAY_DRY_RUN -eq '1') { $DryRun = [switch]$true }
    if ($Preset -notin @('', 'small', 'default')) { throw '-Preset must be small or default' }
    # Extra relay settings (for example RELAY_ALLOW_CIRCLE). They go into a docker argument and a
    # .cmd file, so only a plain character set is allowed.
    $extra = @()
    foreach ($k in ($RelayEnv.Keys | Sort-Object)) {
        $v = [string]$RelayEnv[$k]
        if ($k -cnotmatch '\A[A-Z][A-Z0-9_]*\z') { throw "-RelayEnv: '$k' must be an upper-case setting name" }
        if ($v -cnotmatch '\A[A-Za-z0-9_.,:/@+= -]*\z') { throw "-RelayEnv: the value of $k may hold only letters, digits, spaces and _ . , : / @ + = -" }
        $extra += "$k=$v"
    }
    if (-not $Url) {
        $Url = "wss://localhost:$Port/v3"
        Write-Warning "No -Url: using $Url. Clients only accept the exact public URL (wss://<host>/v3); rerun with -Url once you know it."
    }
    # \A and \z, not ^ and $: $ also matches before a trailing newline.
    if ($Url -cnotmatch '\Awss://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?\z') {
        throw '-Url must look like wss://relay.example.org/v3 (letters, digits and . - _ ~ / only)'
    }
    if ($DataDir) { Test-DataDirPath $DataDir }
    if ($DryRun) { Write-Say 'dry run: nothing will be changed' }

    # ---- detection ---------------------------------------------------------
    $os = Get-Detected 'P2P_DETECT_OS' { if ([Environment]::OSVersion.Platform -eq 'Win32NT') { 'Windows' } else { [Environment]::OSVersion.Platform } }
    if ($os -ne 'Windows') { throw "This script is for Windows; on Linux and macOS use install-relay.sh. (detected: $os)" }
    $arch = Get-Detected 'P2P_DETECT_ARCH' { $env:PROCESSOR_ARCHITECTURE }
    $memText = Get-Detected 'P2P_DETECT_MEM_MB' { [int64]((Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1MB) }
    $memMb = 0
    if (-not [int]::TryParse($memText, [ref]$memMb)) { Write-Warning "couldn't read the RAM size; assuming 2048 MB"; $memMb = 2048 }
    $dockerText = Get-Detected 'P2P_DETECT_DOCKER' { if (Get-Command docker -ErrorAction SilentlyContinue) { & docker version --format '{{.Server.Version}}' 2>$null } }
    $dockerOsType = Get-Detected 'P2P_DETECT_DOCKER_OSTYPE' { if ($dockerText) { & docker info --format '{{.OSType}}' 2>$null } }
    $dockerKernel = Get-Detected 'P2P_DETECT_DOCKER_KERNEL' { if ($dockerText) { & docker info --format '{{.KernelVersion}}' 2>$null } }
    $nodeText = Get-Detected 'P2P_DETECT_NODE' { if (Get-Command node -ErrorAction SilentlyContinue) { & node --version } }
    $wsl2 = $dockerKernel -match 'WSL2|microsoft-standard'
    $backend = if (-not $dockerText) { 'none' } elseif ($dockerOsType -ne 'linux') { "$dockerOsType containers" } elseif ($wsl2) { 'Linux containers on WSL2' } else { 'Linux containers' }
    $label = if ($dockerText) { $dockerText } else { 'none' }
    $nodeLabel = if ($nodeText) { $nodeText } else { 'none' }
    Write-Say "detected: os=$os arch=$arch ram=${memMb}MB docker=$label ($backend) node=$nodeLabel"
    if ($arch -notin @('AMD64', 'ARM64')) { Write-Warning "$arch is not a 64-bit x64 or ARM64 CPU; the relay image is built for amd64 and arm64 only." }

    # ---- sizing ------------------------------------------------------------
    if (-not $Preset) { $Preset = if ($memMb -lt 4096) { 'small' } else { 'default' } }
    if ($Preset -eq 'small') {
        if ($memMb -lt 1536) { $memLimit = 512; $heap = 256 } else { $memLimit = 768; $heap = 384 }
    } else { $memLimit = 1024; $heap = 768 }
    $nodeOptions = "--disable-warning=ExperimentalWarning --max-old-space-size=$heap"
    $bindHost = if ($OpenFirewall) { '0.0.0.0' } else { '127.0.0.1' }
    if ($OpenFirewall) { Write-Warning "-OpenFirewall: the relay will listen on every interface on port $Port, without TLS. Prefer a tunnel (see the guide)." }

    $dockerVersion = ConvertTo-Version $dockerText
    $nodeVersion = ConvertTo-Version $nodeText
    $dockerOk = ($null -ne $dockerVersion) -and ($dockerVersion -ge $minDocker) -and ($dockerOsType -eq 'linux')
    $nodeOk = ($null -ne $nodeVersion) -and ($nodeVersion -ge $minNode)
    if ($Method -eq 'docker' -and -not $dockerOk) { throw "-Method docker needs Docker $minDocker or newer with Linux containers (found: $label, $backend)" }
    if ($Method -eq 'node' -and -not $nodeOk) { throw "-Method node needs Node $minNode or newer (found: $nodeLabel)" }
    $useDocker = $dockerOk -and $Method -ne 'node'
    $useNode = -not $useDocker -and $nodeOk -and $Method -ne 'docker'

    # Elevated steps, built as script text so the elevated process gets values, not this script's path.
    $elevated = New-Object System.Collections.Generic.List[string]

    if ($useDocker) {
        Write-Say "plan: Docker $dockerText ($backend), preset $Preset, memory cap ${memLimit}m, heap $heap MiB"
        $src = Get-RelaySource
        if (-not $DryRun) {
            & docker container inspect $name *> $null
            if ($LASTEXITCODE -eq 0 -and -not $Replace) { throw "A container named $name exists; rerun with -Replace to rebuild and replace it (its data volume is kept)." }
        }
        if ($DataDir) {
            $state = Get-DirState $DataDir
            if ($state -eq 'foreign') { throw "-DataDir $DataDir already holds files that aren't the relay's; use a new or empty folder." }
            if (-not $DryRun) {
                New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
                Set-Content -LiteralPath (Join-Path $DataDir '.p2p-relay') -Value 'Peer2Peer relay data (install-relay.ps1)' -Encoding ASCII
            }
            $mount = "type=bind,source=$DataDir,target=/data"
        } else {
            $mount = 'type=volume,source=p2p-relay-data,target=/data'
        }
        $dockerfile = Join-Path $src 'packages/relay/Dockerfile'
        $env:DOCKER_BUILDKIT = '1'
        Invoke-Step 'docker' @('build', '-f', $dockerfile, '-t', $image, $src)
        if ($Replace) { Invoke-Step 'docker' @('rm', '-f', $name) }
        Invoke-Step 'docker' (@('run', '-d', '--name', $name, '--restart', 'unless-stopped',
            '-p', "${bindHost}:${Port}:8080", '--mount', $mount,
            '-e', "RELAY_URL=$Url", '-e', "RELAY_PRESET=$Preset", '-e', "NODE_OPTIONS=$nodeOptions", '-e', 'TRUST_PROXY=1',
            '--memory', "${memLimit}m", '--memory-swap', "${memLimit}m", '--pids-limit', '128',
            '--read-only', '--tmpfs', '/tmp:size=16m', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--log-opt', 'max-size=10m', '--log-opt', 'max-file=3') +
            @($extra | ForEach-Object { '-e', $_ }) + @($image))
    } elseif ($useNode) {
        $nodeBin = if ($env:P2P_NODE_BIN) { $env:P2P_NODE_BIN } else { (Get-Command node).Source }
        if ($nodeBin -cnotmatch '\A[A-Za-z]:\\[A-Za-z0-9_.\\ ()-]+\\node\.exe\z') { throw "node.exe is at an unexpected path ($nodeBin); install Node 22 for all users and rerun." }
        if (($env:USERPROFILE -and $nodeBin.StartsWith("$env:USERPROFILE\", [StringComparison]::OrdinalIgnoreCase)) -or $nodeBin -like 'C:\Users\*') {
            throw "node is at $nodeBin, which the relay's account can't read. Install Node 22 for all users (https://nodejs.org/en/download) and rerun."
        }
        $installDir = "$env:ProgramData\p2p-relay"
        if ($installDir -cnotmatch '\A[A-Za-z]:\\[A-Za-z0-9_.\\ -]+\z') { throw "ProgramData is at an unexpected path ($installDir)" }
        if (-not $DataDir) { $DataDir = "$installDir\data" }
        # The elevated step changes these folders' owner and ACL. If you could delete, rename or
        # re-permission any folder above them (from the drive root down), you could swap one for a
        # link in between, so that is refused. The same check runs again, elevated.
        $userSids = Get-UserSid
        foreach ($d in @($installDir, $DataDir)) {
            $a = Get-SwappableAncestor $d $userSids
            if ($a) {
                throw "${d}: you can change the folder $a above it without administrator rights. Pick a folder whose parents only administrators can change (for example create it in an elevated prompt and remove other users' rights), or leave -DataDir out."
            }
        }
        if ((Get-DirState $installDir -OverrideVar 'P2P_DETECT_INSTALLDIR_STATE' -AdminOnly) -eq 'foreign') {
            throw "$installDir already exists, isn't owned by Administrators and isn't empty; remove it (it may have been created by another user) and rerun."
        }
        if ((Get-DirState $DataDir -AdminOnly) -eq 'foreign') { throw "-DataDir $DataDir already holds files that aren't the relay's, or belongs to another user; use a new or empty folder." }
        Write-Say "plan: Node $nodeText, Scheduled Task as local account p2p-relay, preset $Preset, heap $heap MiB, install in $installDir, database in $DataDir"
        if (-not $DryRun -and (Test-Path "$installDir\app") -and -not $Replace) { throw "$installDir exists; rerun with -Replace to upgrade it." }
        $src = Get-RelaySource

        # Build as you, in a temporary copy, the way the Dockerfile does.
        $stage = Join-Path ([IO.Path]::GetTempPath()) ('p2p-relay-build-' + [guid]::NewGuid().ToString('N'))
        Write-Say "+ copy packages/core and packages/relay to $stage, then npm ci and build each"
        if (-not $DryRun) {
            New-Item -ItemType Directory -Path (Join-Path $stage 'packages') | Out-Null
            foreach ($p in 'core', 'relay') {
                Copy-Item -Recurse -Path (Join-Path $src "packages/$p") -Destination (Join-Path $stage "packages/$p")
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -Path (Join-Path $stage "packages/$p/node_modules")
            }
        }
        foreach ($p in 'core', 'relay') {
            $dir = Join-Path $stage "packages/$p"
            Invoke-Step 'npm.cmd' @('ci', '--prefix', $dir, '--ignore-scripts', '--no-audit', '--no-fund')
            Invoke-Step 'npm.cmd' @('run', '--prefix', $dir, 'build')
        }
        foreach ($p in 'core', 'relay') {
            Invoke-Step 'npm.cmd' @('ci', '--prefix', (Join-Path $stage "packages/$p"), '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund')
        }
        # npm links the relay to core with a junction. The elevated copy skips every link (robocopy
        # /XJ), so replace this one with a real copy; nothing in the tree then points outside it.
        $link = Join-Path $stage 'packages/relay/node_modules/@peer2peer/core'
        Write-Say "+ replace the link $link with a copy of packages/core"
        if (-not $DryRun) {
            [IO.Directory]::Delete($link, $false)
            Copy-Item -Recurse -Path (Join-Path $stage 'packages/core') -Destination $link
        }

        $q = { param($s) "'" + ($s -replace "'", "''") + "'" }
        $cmd = (@(
            '@echo off',
            "set `"RELAY_URL=$Url`"",
            "set `"HOST=$bindHost`"",
            "set `"PORT=$Port`"",
            "set `"DB_PATH=$DataDir\relay.db`"",
            "set `"RELAY_PRESET=$Preset`"",
            'set "TRUST_PROXY=1"',
            "set `"NODE_OPTIONS=$nodeOptions`""
        ) + @($extra | ForEach-Object { "set `"$_`"" }) + @(
            "`"$nodeBin`" `"$installDir\app\packages\relay\dist\bin.js`" >> `"$DataDir\relay.log`" 2>&1"
        )) -join "`r`n"
        # Every value above was checked against a strict character set; the elevated step gets
        # them as single-quoted literals, then runs fixed code.
        $elevated.Add(("`$installDir = {0}; `$dataDir = {1}; `$stage = {2}; `$cmdText = {3}; `$P2PElevated = `$true" -f (& $q $installDir), (& $q $DataDir), (& $q $stage), (& $q $cmd)))
        $elevated.Add($rightsLib)
        # The installing user's SIDs come from the elevated step's own token, not from here.
        $elevated.Add('$userSids = Get-UserSid')
        $elevated.Add(@'
function Assert-NotLink([string]$Path) {
    if ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$Path is a link; refusing to use it" }
}
function Get-OwnerSid([string]$Path) { (Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value }
# Owners that are fine: Administrators, SYSTEM, and this elevated session's own account.
$trusted = @('S-1-5-32-544', 'S-1-5-18', [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
$relayUser = Get-LocalUser -Name 'p2p-relay' -ErrorAction SilentlyContinue
$relaySid = if ($relayUser) { $relayUser.SID.Value } else { '' }
# Refuse to take over a folder that already holds someone else's files. A folder another user
# owns is never trusted (anyone can create %ProgramData%\p2p-relay first): if it is empty it is
# deleted and created again below, as Administrators'; otherwise the install stops.
foreach ($d in @($installDir, $dataDir)) {
    if (Test-Path -LiteralPath $d) {
        Assert-NotLink $d
        $owner = Get-OwnerSid $d
        $empty = -not (Get-ChildItem -LiteralPath $d -Force | Select-Object -First 1)
        $marked = Test-Path -LiteralPath (Join-Path $d '.p2p-relay')
        if ($trusted -contains $owner) {
            if (-not ($marked -or $empty)) { throw "$d already holds files that aren't the relay's; use a new or empty folder" }
        } elseif ($relaySid -and $owner -eq $relaySid -and $d -eq $dataDir) {
            # The relay's own data from an earlier install.
        } elseif ($empty) {
            [IO.Directory]::Delete($d, $false)
        } else {
            throw "$d belongs to another account ($owner) and isn't empty; remove it and rerun"
        }
    }
}
# Nothing above either folder may be changeable by the user who started the install.
foreach ($d in @($installDir, $dataDir)) {
    $a = Get-SwappableAncestor $d $userSids
    if ($a) { throw "${d}: the folder $a above it can be changed by the user who started this install" }
}
# Create what is missing one folder at a time, each born locked (New-LockedDirectory), and check
# that each new folder is ours: a folder someone else slipped in first makes the install stop.
function New-TrustedDir([string]$Path) {
    foreach ($c in (Get-WindowsChain $Path)) {
        if (Test-Path -LiteralPath $c) { continue }
        New-LockedDirectory $c
        Assert-NotLink $c
        if ($trusted -notcontains (Get-OwnerSid $c)) { throw "$c was created by another account during the install; remove it and rerun" }
    }
}
# Lock both folders first, before anything slow: Administrators own them and only Administrators
# and SYSTEM may change them. The relay's account is granted access at the end.
foreach ($d in @($installDir, $dataDir)) {
    New-TrustedDir $d
    Assert-NotLink $d
    $owner = Get-OwnerSid $d
    if (-not (($trusted -contains $owner) -or ($relaySid -and $owner -eq $relaySid -and $d -eq $dataDir))) { throw "$d belongs to another account ($owner); remove it and rerun" }
    Assert-NotLink $d
    & icacls.exe $d /setowner '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls /setowner failed on $d" }
    Assert-NotLink $d
    & icacls.exe $d /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $d" }
}
# A local account for the relay, in no group, with a random password only Task Scheduler keeps.
$chars = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+-.=?@_'
$rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $bytes = New-Object byte[] 40; $rng.GetBytes($bytes)
$plain = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
$secure = New-Object Security.SecureString; foreach ($c in $plain.ToCharArray()) { $secure.AppendChar($c) }
if (Get-LocalUser -Name 'p2p-relay' -ErrorAction SilentlyContinue) { Set-LocalUser -Name 'p2p-relay' -Password $secure -PasswordNeverExpires $true }
else { New-LocalUser -Name 'p2p-relay' -Password $secure -PasswordNeverExpires -UserMayNotChangePassword -Description 'Peer2Peer relay (install-relay.ps1)' | Out-Null }
Get-ScheduledTask -TaskName 'p2p-relay' -ErrorAction SilentlyContinue | Stop-ScheduledTask
# Stopping the task ends cmd.exe; end the relay's node.exe too, so its files can be replaced.
Get-CimInstance -ClassName Win32_Process -Filter "Name = 'node.exe'" | Where-Object { (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User -eq 'p2p-relay' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
# Install folder: Administrators and SYSTEM full control, the relay's account read-only.
Assert-NotLink $installDir
& icacls.exe $installDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' 'p2p-relay:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'icacls failed on the install folder' }
Set-Content -LiteralPath (Join-Path $installDir '.p2p-relay') -Value 'Peer2Peer relay (install-relay.ps1)' -Encoding ASCII
# Copy the build without following any link in it (robocopy /XJ), so nothing outside it is read as Administrator.
if (Test-Path "$installDir\app") { Remove-Item -Recurse -Force "$installDir\app" }
& robocopy.exe $stage "$installDir\app" /E /XJ /R:0 /W:0 /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "copying the relay failed (robocopy exit code $LASTEXITCODE)" }
Set-Content -Path "$installDir\run-relay.cmd" -Encoding ASCII -Value $cmdText
# Data folder: the relay's account owns it and may modify it.
Assert-NotLink $dataDir
& icacls.exe $dataDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' 'p2p-relay:(OI)(CI)M' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'icacls failed on the data folder' }
Assert-NotLink $dataDir
& icacls.exe $dataDir /setowner 'p2p-relay' | Out-Null
# User rights: the account may run as a batch job (the task) and may not sign in interactively or
# over Remote Desktop. secedit works on every edition (ntrights isn't shipped any more).
$sid = (Get-LocalUser -Name 'p2p-relay').SID.Value
$sec = Join-Path $installDir 'secedit'
New-Item -ItemType Directory -Force -Path $sec | Out-Null
$inf = Join-Path $sec 'rights.inf'
& secedit.exe /export /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'secedit /export failed' }
$lines = New-Object System.Collections.Generic.List[string]
foreach ($l in (Get-Content -LiteralPath $inf)) { $lines.Add($l) }
foreach ($right in 'SeBatchLogonRight', 'SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight') {
    $at = -1
    for ($n = 0; $n -lt $lines.Count; $n++) { if ($lines[$n] -like "$right *") { $at = $n } }
    if ($at -ge 0) {
        if ($lines[$at] -notmatch [regex]::Escape("*$sid")) { $lines[$at] = $lines[$at] + ",*$sid" }
    } else {
        $lines.Insert($lines.IndexOf('[Privilege Rights]') + 1, "$right = *$sid")
    }
}
Set-Content -LiteralPath $inf -Value $lines -Encoding Unicode
& secedit.exe /configure /db (Join-Path $sec 'rights.sdb') /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'secedit /configure failed' }
Remove-Item -Recurse -Force -LiteralPath $sec
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument "/d /c `"`"$installDir\run-relay.cmd`"`"" -WorkingDirectory $installDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -StartWhenAvailable
Register-ScheduledTask -TaskName 'p2p-relay' -Description 'Peer2Peer relay' -Action $action -Trigger $trigger -Settings $settings -User "$env:COMPUTERNAME\p2p-relay" -Password $plain -RunLevel Limited -Force | Out-Null
$plain = $null
Start-ScheduledTask -TaskName 'p2p-relay'
'@)
    } else {
        Write-Say ''
        Write-Say 'Nothing to install with yet. Missing:'
        if (-not $dockerText) { Write-Say "  - Docker Desktop (Docker $minDocker or newer) with Linux containers: not found, or its engine isn't running." }
        elseif ($dockerOsType -ne 'linux') { Write-Say "  - Docker is running $dockerOsType containers: switch Docker Desktop to Linux containers (WSL2 backend)." }
        else { Write-Say "  - Docker $minDocker or newer: found $dockerText." }
        Write-Say "  - Node $minNode or newer: found $nodeLabel."
        Write-Say ''
        Write-Say 'Options:'
        Write-Say '  - Install Docker Desktop with the WSL2 backend: https://docs.docker.com/desktop/setup/install/windows-install/'
        Write-Say '  - Or install Node 22 for all users: https://nodejs.org/en/download'
        Write-Say '  - Or run the relay on another machine: docs/run-a-relay-on-any-machine.md'
        return
    }

    if ($OpenFirewall) {
        $elevated.Add("New-NetFirewallRule -DisplayName 'Peer2Peer relay' -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -Profile Private | Out-Null")
    }

    if ($elevated.Count -gt 0) {
        $body = "`$ErrorActionPreference = 'Stop'`r`n" + ($elevated -join "`r`n")
        $what = @()
        if ($useNode) { $what += 'create the p2p-relay account, copy the relay into %ProgramData%\p2p-relay, and register its Scheduled Task' }
        if ($OpenFirewall) { $what += "add a Windows Firewall rule for TCP port $Port (Private networks)" }
        Write-Say ("Administrator rights are needed for the next step only: " + ($what -join '; ') + '.')
        if ($DryRun) {
            Write-Say '+ elevated:'
            $body -split "`r`n" | Where-Object { $_ -notmatch '^\$ErrorActionPreference' } | ForEach-Object { Write-Say "    $_" }
        } else {
            $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
            if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                & ([scriptblock]::Create($body))
            } else {
                # The script goes on the elevated process's command line (-EncodedCommand), never into a
                # file a non-admin could change between writing and running it.
                $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
                if ($encoded.Length -gt 30000) { throw 'internal: the elevated step is too long for one command line' }
                $p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded)
                if ($p.ExitCode -ne 0) { throw "the elevated step failed (exit code $($p.ExitCode))" }
            }
        }
        if ($useNode -and -not $DryRun) { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $stage }
    }

    if (-not (Wait-Healthy)) {
        if ($useDocker) { throw "The relay didn't become healthy; see: docker logs $name" }
        throw "The relay didn't become healthy; see $DataDir\relay.log and the p2p-relay task in Task Scheduler."
    }
    Write-Say ''
    if ($DryRun) { Write-Say "Dry run done: the relay would listen on http://${bindHost}:$Port." }
    else { Write-Say "The relay is running on http://${bindHost}:$Port (health: /healthz)." }
    Write-Say "Give teammates this relay URL: $Url"
    Write-Say 'Put a tunnel or a TLS proxy in front (Tailscale serve, Cloudflare Tunnel or Caddy): docs/run-a-relay-on-any-machine.md'
}

Install-P2PRelay @PSBoundParameters
