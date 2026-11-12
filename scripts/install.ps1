# Copyright 2026 Ix Infrastructure Inc.
# SPDX-License-Identifier: Apache-2.0
#
# install.ps1: install the Peer2Peer client (the `p2p` command) on Windows.
# PowerShell 5.1 or newer; no Administrator rights needed.
#
#   irm https://ix-infra.com/p2p/install.ps1 | iex
#   & ([scriptblock]::Create((irm https://ix-infra.com/p2p/install.ps1))) -DryRun
#   .\install.ps1 [-Version X.Y.Z] [-NoSetup] [-DryRun]     # from a checkout or a download
#
# With `| iex` there are no parameters: set P2P_INSTALL_VERSION,
# P2P_INSTALL_NO_SETUP=1 or P2P_INSTALL_DRY_RUN=1 first, or use the scriptblock form.
#
# What it does:
#   1. Checks for Node.js >= 22 and npm. If either is missing or too old, it
#      prints how to get them (winget, nodejs.org) and stops: it never
#      installs Node itself.
#   2. Checks that npm's global folder is writable by you. If it isn't, it
#      explains how to point npm at a folder of your own and stops: it never
#      asks for elevation.
#   3. Runs `npm install -g` for @peer2peer/cli and @peer2peer/ext-ix, pinned
#      to exactly $P2PVersion, and checks the result with `p2p --version`.
#      npm checks each package against the registry's integrity hash; nothing
#      is downloaded any other way, and no package install scripts run.
#   4. In an interactive console, hands over to `p2p setup`, which asks its own
#      questions. Without one it skips setup and says to run `p2p setup`.
#   It doesn't install Ix or anything else.
#
# Every command is printed (as "+ ...") before it runs.
#
# Safe to pipe: everything is inside Install-P2PClient, called on the last
# line, so a truncated download runs nothing. It never relies on its own path,
# and it reports errors by throwing, never with `exit`, so `| iex` can't close
# your PowerShell window.
#
# Detection can be overridden for testing: P2P_DETECT_OS (Windows),
# P2P_DETECT_NODE, P2P_DETECT_NPM, P2P_DETECT_PREFIX_WRITABLE (yes/no),
# P2P_DETECT_TTY (yes/no). Set a P2P_DETECT_* variable to "none" for "not found".

[CmdletBinding()]
param(
    [string]$Version = '',
    [switch]$NoSetup,
    [switch]$DryRun
)

function Install-P2PClient {
    [CmdletBinding()]
    param(
        [string]$Version = '',
        [switch]$NoSetup,
        [switch]$DryRun
    )
    Set-StrictMode -Version 2.0
    $ErrorActionPreference = 'Stop'

    # The release these scripts install; bumped after each release (docs/releasing.md, step 5).
    $P2PVersion = '0.1.1'
    $packages = @('@peer2peer/cli', '@peer2peer/ext-ix')
    $minNode = [version]'22.0.0'

    function Write-Say([string]$Message) { Write-Information -MessageData $Message -InformationAction Continue }

    # Runs a native command, printing it first; does nothing in a dry run.
    function Invoke-Step([string]$Exe, [string[]]$Arguments) {
        $shown = ($Arguments | ForEach-Object { if ($_ -match '[\s"]') { "'" + $_ + "'" } else { $_ } }) -join ' '
        $exeShown = if ($Exe -match '\s') { "'" + $Exe + "'" } else { $Exe }
        Write-Say "+ $exeShown $shown"
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

    # On Windows npm is npm.cmd: calling it directly (not the npm.ps1 shim) works
    # whatever the execution policy is.
    $onWindowsHost = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    function Find-Exe([string]$Name) {
        $names = if ($onWindowsHost) { @("$Name.cmd", "$Name.exe") } else { @($Name) }
        foreach ($n in $names) {
            $c = Get-Command -Name $n -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($c) { return $c.Source }
        }
        return ''
    }

    # Parameters win; with `| iex` there are none, so the environment can set them.
    if (-not $Version -and $env:P2P_INSTALL_VERSION) { $Version = $env:P2P_INSTALL_VERSION }
    if (-not $Version) { $Version = $P2PVersion }
    if (-not $NoSetup -and $env:P2P_INSTALL_NO_SETUP -eq '1') { $NoSetup = [switch]$true }
    if (-not $DryRun -and $env:P2P_INSTALL_DRY_RUN -eq '1') { $DryRun = [switch]$true }

    # An exact npm version (1.2.3 or 1.2.3-rc.1), never a range or a tag.
    if ($Version -cnotmatch '\A[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?\z') {
        throw "-Version must be an exact version such as $P2PVersion (got '$Version')."
    }
    $specs = @($packages | ForEach-Object { "$_@$Version" })
    if ($DryRun) { Write-Say 'dry run: nothing will be changed' }

    $os = Get-Detected 'P2P_DETECT_OS' { if ($onWindowsHost) { 'Windows' } else { 'other' } }
    if ($os -ne 'Windows') { throw "This script is for Windows; on macOS and Linux use install.sh (curl -fsSL https://ix-infra.com/p2p/install.sh | sh). (detected: $os)" }
    $npmExe = Find-Exe 'npm'
    $nodeV = Get-Detected 'P2P_DETECT_NODE' { $n = Find-Exe 'node'; if ($n) { & $n --version } }
    $npmV = Get-Detected 'P2P_DETECT_NPM' { if ($npmExe) { & $npmExe --version } }
    Write-Say "detected: os=$os node=$(if ($nodeV) { $nodeV } else { 'none' }) npm=$(if ($npmV) { $npmV } else { 'none' }) powershell=$($PSVersionTable.PSVersion)"

    $nodeVer = ConvertTo-Version $nodeV
    if (-not $nodeVer -or -not $npmV -or -not $npmExe -or $nodeVer -lt $minNode) {
        Write-Say ''
        Write-Say "Peer2Peer needs Node.js $minNode or newer, with npm. Found: node $(if ($nodeV) { $nodeV } else { 'none' }), npm $(if ($npmV) { $npmV } else { 'none' })."
        Write-Say "This script doesn't install Node. Pick one, then run it again in a new PowerShell window:"
        Write-Say '  - winget (Windows 10/11): winget install OpenJS.NodeJS.LTS'
        Write-Say '  - The installer from https://nodejs.org/en/download (LTS)'
        Write-Say '  - nvm for Windows (several Node versions side by side): https://github.com/coreybutler/nvm-windows, then: nvm install 22'
        throw "Node.js $minNode or newer and npm are needed (see above)."
    }

    # npm's global folder: on Windows the p2p.cmd shim goes straight into it.
    $prefix = ([string](& $npmExe prefix -g)).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $prefix) { throw "couldn't read npm's global folder (npm prefix -g)" }
    $p2pExe = Join-Path $prefix 'p2p.cmd'
    $writable = Get-Detected 'P2P_DETECT_PREFIX_WRITABLE' {
        try {
            $probe = Join-Path $prefix ('.p2p-install-probe-' + [guid]::NewGuid().ToString('N'))
            if (-not (Test-Path -LiteralPath $prefix)) { $probe = Join-Path (Split-Path -Parent $prefix) ('.p2p-install-probe-' + [guid]::NewGuid().ToString('N')) }
            [IO.File]::WriteAllText($probe, '')
            Remove-Item -LiteralPath $probe -Force
            'yes'
        } catch { 'no' }
    }
    if ($writable -ne 'yes') {
        Write-Say ''
        Write-Say "npm installs global packages into $prefix, which isn't writable by you."
        Write-Say "This script doesn't ask for Administrator rights. Point npm at a folder of your own, add it to your PATH, and run this again:"
        Write-Say '    npm config set prefix "$env:APPDATA\npm"'
        Write-Say '    [Environment]::SetEnvironmentVariable(''Path'', [Environment]::GetEnvironmentVariable(''Path'', ''User'') + '';'' + "$env:APPDATA\npm", ''User'')'
        if ($DryRun) { Write-Say '(dry run: continuing to show the plan)' }
        else { throw "npm's global folder $prefix isn't writable (see above)." }
    }

    Write-Say "plan: install $($specs -join ' ') into $prefix with npm, then check $p2pExe --version"
    Invoke-Step $npmExe (@('install', '-g', '--ignore-scripts', '--no-fund', '--no-audit') + $specs)

    if ($DryRun) {
        Write-Say "+ $p2pExe --version   (expect $Version)"
    } else {
        if (-not (Test-Path -LiteralPath $p2pExe)) { throw "npm finished but $p2pExe isn't there; run: npm ls -g @peer2peer/cli" }
        $got = ([string](& $p2pExe --version | Select-Object -First 1)).Trim()
        if ($got -ne $Version) { throw "$p2pExe --version printed '$got', expected $Version" }
        Write-Say "Installed: p2p $got ($p2pExe)"
    }

    $onPath = @(($env:Path -split ';') | Where-Object { $_ -and $_.TrimEnd('\') -ieq $prefix.TrimEnd('\') }).Count -gt 0
    if (-not $onPath) {
        Write-Warning "$prefix isn't on your PATH: add it (Settings > System > About > Advanced system settings > Environment Variables), or open a new PowerShell window."
    }

    if ($NoSetup) {
        Write-Say 'Next: run `p2p setup` to create your identity.'
    } else {
        $tty = Get-Detected 'P2P_DETECT_TTY' {
            $nonInteractive = [Environment]::GetCommandLineArgs() | Where-Object { $_ -match '^-NonI' }
            if ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected -and -not $nonInteractive) { 'yes' } else { 'no' }
        }
        if ($tty -eq 'yes') {
            Write-Say ''
            Write-Say 'Now setting up your identity (p2p setup):'
            Write-Say "+ $p2pExe setup"
            if (-not $DryRun) {
                & $p2pExe setup
                if ($LASTEXITCODE -ne 0) { Write-Warning 'p2p setup did not finish; run `p2p setup` to try again.' }
            }
        } else {
            Write-Say 'No console to ask questions on, so setup was skipped. Next: run `p2p setup` to create your identity.'
        }
    }
    if ($DryRun) { Write-Say 'Dry run done: nothing was installed.' }
}

Install-P2PClient @PSBoundParameters
