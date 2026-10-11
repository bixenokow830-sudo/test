<#
  init-backup.ps1 -- portable git backup bootstrapper (Windows / PowerShell 5.1+)

  NO DSH DEPENDENCY. Pure ASCII on purpose so it survives being copied between
  machines (Windows PowerShell 5.1 reads BOM-less files as ANSI, which would
  corrupt non-ASCII comments and break parsing).

  WHAT IT DOES
    1. locate the project directory
    2. git init only when it is not already a repository
    3. set repository-local identity (never touches global config)
    4. write .gitignore / .gitattributes, or APPEND missing rules when the
       project already has them (existing content is never overwritten)
    5. scan for secret-looking files and refuse to commit them
    6. stage, show the exact file list, commit
    7. add the remote when given, then push via the system proxy if one is live

  USAGE
    powershell -NoProfile -ExecutionPolicy Bypass -File init-backup.ps1 `
        -ProjectDir "D:\work\myproject" `
        -Remote "https://github.com/<owner>/<repo>.git"

    -ProjectDir   project folder            (default: current directory)
    -Remote       GitHub HTTPS URL          (optional; without it, no push)
    -Message      commit message            (default: dated auto message)
    -Name/-Email  commit identity           (default: derived locally)
    -Branch       branch name               (default: main)
    -DryRun       show the plan, change nothing
    -NoPush       commit locally, never push

  EXIT CODES
    0 success | 1 error | 2 push failed (local commit is safe) | 3 diverged
#>
[CmdletBinding()]
param(
  [string]$ProjectDir = '',
  [string]$Remote = '',
  [string]$Message = '',
  [string]$Name = '',
  [string]$Email = '',
  [string]$Branch = 'main',
  [switch]$DryRun,
  [switch]$NoPush
)

# Deliberately NOT 'Stop'. PowerShell converts any stderr line from a native
# command (git) into an error record; under 'Stop' that becomes a terminating
# exception even when git succeeded, which produced false "push failed"
# reports. This script decides success by EXIT CODES only.
$ErrorActionPreference = 'Continue'

$exitOk = 0; $exitErr = 1; $exitPushFail = 2; $exitDiverged = 3

function Say      ($t) { Write-Host $t }
function Head     ($t) { Write-Host ''; Write-Host "== $t" -ForegroundColor Cyan }
function Ok       ($t) { Write-Host "   $t" -ForegroundColor Green }
function Warn     ($t) { Write-Host "   $t" -ForegroundColor Yellow }
function Bad      ($t) { Write-Host "   $t" -ForegroundColor Red }

# Write UTF-8 WITHOUT a BOM. Set-Content -Encoding UTF8 emits a BOM in Windows
# PowerShell 5.1, so appending an array of lines that already carry one would
# leave a stray U+FEFF in the middle of the file.
function Write-Lines {
  param([string]$Path, [string[]]$Lines)
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllLines($Path, [string[]]$Lines, $utf8NoBom)
}

$GITIGNORE_RULES = @(
  '# --- secrets and environment ---',
  '.env', '.env.*', '*.pem', '*.key', '*.p12', 'id_rsa*', 'credentials*', '*secret*',
  '# --- tool session/backup data (not project artifacts) ---',
  '*-backup-*/', '*-backup-*', 'storages/', 'sessions/',
  '# --- dependencies and build output ---',
  'node_modules/', '__pycache__/', '.venv/', 'venv/', 'dist/', 'build/', 'target/',
  '*.pyc', '*.class', '*.o', '*.obj', '*.exe', '*.dll',
  '# --- OS / editor junk ---',
  'Thumbs.db', 'ehthumbs.db', 'Desktop.ini', '.DS_Store', '.vscode/', '.idea/',
  '*.tmp', '*.log', '~$*'
)

$GITATTRIBUTES_RULES = @(
  '* text=auto',
  '*.cmd text eol=crlf',
  '*.bat text eol=crlf',
  '*.ps1 text eol=crlf',
  '*.png binary',
  '*.jpg binary',
  '*.zip binary'
)

# Secret detection is deliberately split into simple, testable parts instead of
# one large regex -- a single expression here is easy to get subtly wrong.
#   documentation extensions win (a guide ABOUT api keys is not a key)
#   secret extensions are refused outright
#   otherwise the file NAME is matched against credential keywords
$SECRET_EXTENSIONS = @('.pem', '.key', '.p12', '.pfx', '.keystore', '.jks', '.ppk', '.asc', '.gpg')
$DOC_EXTENSIONS    = @('.md', '.rst', '.adoc')
$SECRET_NAME_PATTERN = '(?i)(^|[\\/])(secrets?|credentials?)([\\/]|$)|(password|passwd|passphrase|apikey|api[-_]?keys?|access[-_]key|private[-_]key|credential|secret|id_rsa)|^\.env'

function Test-SecretPath {
  param([string]$Path)
  $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
  if ($DOC_EXTENSIONS -contains $ext) { return $false }
  if ($SECRET_EXTENSIONS -contains $ext) { return $true }
  return [regex]::IsMatch($Path, $SECRET_NAME_PATTERN)
}

# Content keywords: a warning only, since these can appear in documentation.
$SECRET_CONTENT_PATTERN = 'AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY|password\s*[:=]\s*\S|secret\s*[:=]\s*\S|token\s*[:=]\s*[''"]?[A-Za-z0-9_\-]{16,}'

function Resolve-RepoRoot {
  param([string]$Start)
  $top = & git -C $Start rev-parse --show-toplevel 2>$null
  if ($LASTEXITCODE -eq 0 -and $top) { return ([string]$top).Trim() }
  return $null
}

# Detect a live local proxy. Direct github.com connections frequently time out
# on machines that already run Clash/v2ray, because git ignores the system proxy.
function Get-LocalProxy {
  try {
    $ie = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
    if (-not $ie.ProxyEnable -or -not $ie.ProxyServer) { return $null }
    $server = [string]$ie.ProxyServer
    if ($server -match '=') {
      $server = ($server -split ';' | Where-Object { $_ -match '^https?=' } | Select-Object -First 1) -replace '^https?=', ''
    }
    $server = $server.Trim()
    if ($server -notmatch '^(?<h>[^:]+):(?<p>\d+)$') { return $null }
    $hostName = $Matches['h']; $port = [int]$Matches['p']
    $client = New-Object System.Net.Sockets.TcpClient
    try {
      if ($client.ConnectAsync($hostName, $port).Wait(700) -and $client.Connected) {
        return "http://${hostName}:${port}"
      }
    } finally { $client.Close() }
  } catch { return $null }
  return $null
}

function Invoke-GitNet {
  param([string[]]$Arguments, [string]$Proxy, [switch]$Quiet)
  $argv = @('-C', $script:repo, '-c', 'http.connectTimeout=8000')
  if ($Proxy) { $argv += @('-c', "http.proxy=$Proxy") }
  $argv += $Arguments
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    if ($Quiet) {
      # A missing remote branch is normal on the very first push, and its
      # "fatal: couldn't find remote ref" text only alarms the reader.
      & git @argv 2>$null | Out-Null
    } else {
      & git @argv 2>&1 | ForEach-Object { Write-Host "   $_" }
    }
    $code = $LASTEXITCODE
  } finally { $ErrorActionPreference = $prev }
  return $code
}

function Add-MissingLines {
  param([string]$Path, [string[]]$Lines, [string]$Title)
  $existing = @()
  if (Test-Path -LiteralPath $Path) {
    $existing = @(Get-Content -LiteralPath $Path -Encoding UTF8)
  }
  $missing = @($Lines | Where-Object { $existing -notcontains $_ })
  if ($missing.Count -eq 0) { Ok "$Title already covers every rule"; return }
  if ($DryRun) { Ok "would add $($missing.Count) rule(s) to $Title"; return }
  $block = @()
  $block += ''
  $block += "# --- added by init-backup.ps1 ---"
  $block += $missing
  Add-Content -LiteralPath $Path -Value $block -Encoding UTF8
  Ok "added $($missing.Count) rule(s) to $Title"
}

# ---------------- main ----------------

$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if (-not $gitCmd) { Bad 'git is not installed or not on PATH'; exit $exitErr }

if (-not $ProjectDir) { $ProjectDir = (Get-Location).Path }
if (-not (Test-Path -LiteralPath $ProjectDir)) { Bad "project directory not found: $ProjectDir"; exit $exitErr }
$ProjectDir = (Resolve-Path -LiteralPath $ProjectDir).Path

Head 'Project'
Ok $ProjectDir

$alreadyRepo = Test-Path -LiteralPath (Join-Path $ProjectDir '.git')
if (-not $alreadyRepo) {
  $outer = Resolve-RepoRoot -Start $ProjectDir
  if ($outer -and $outer -ne $ProjectDir) {
    Warn "this directory is already INSIDE the git work tree: $outer"
    Warn 'a nested repository would be confusing. Use that repository instead, or pass a different directory.'
    exit $exitErr
  }
}

if ($DryRun) { Warn 'DRY RUN: nothing will be created, committed, or pushed' }

Head 'Repository'
if ($alreadyRepo) {
  Ok 'already a git repository (will not re-initialize)'
} else {
  if ($DryRun) { Ok "would run: git init -b $Branch" }
  else {
    & git -C $ProjectDir init -q -b $Branch 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Bad 'git init failed'; exit $exitErr }
    Ok "initialized with branch $Branch"
  }
}
$script:repo = $ProjectDir

Head 'Identity (repository-local only)'
if (-not $Name) {
  $Name = & git -C $ProjectDir config user.name 2>$null
  if (-not $Name) { $Name = $env:USERNAME }
}
if (-not $Email) {
  $Email = & git -C $ProjectDir config user.email 2>$null
  # Windows account names often contain spaces; a mail address must not.
  if (-not $Email) { $Email = (($Name -replace '\s+', '-') + '@' + $env:COMPUTERNAME + '.local') }
}
if (-not $DryRun) {
  & git -C $ProjectDir config user.name $Name 2>&1 | Out-Null
  & git -C $ProjectDir config user.email $Email 2>&1 | Out-Null
  & git -C $ProjectDir config core.quotepath false 2>&1 | Out-Null
}
Ok "user.name  = $Name"
Ok "user.email = $Email"
Warn 'change them with: git config user.email "you@example.com"'

Head 'Ignore rules'
Add-MissingLines -Path (Join-Path $ProjectDir '.gitignore')    -Lines $GITIGNORE_RULES    -Title '.gitignore'
Add-MissingLines -Path (Join-Path $ProjectDir '.gitattributes') -Lines $GITATTRIBUTES_RULES -Title '.gitattributes'

Head 'Stage'
if ($DryRun) {
  if ($alreadyRepo) {
    Ok 'would run: git add -A'
  } else {
    Ok 'would run: git init, then git add -A'
    Head 'Every file currently in the directory (the rules above would be applied first)'
    # The .gitignore does not exist yet in a dry run, so this listing is the raw
    # directory contents -- it shows what is at stake before the rules apply.
    $all = @(Get-ChildItem -LiteralPath $ProjectDir -Recurse -Force -File |
      Where-Object { $_.FullName -notmatch '\\\.git\\' } |
      ForEach-Object { $_.FullName.Substring($ProjectDir.Length + 1) })
    $all | Select-Object -First 40 | ForEach-Object { Write-Host "   $_" }
    if ($all.Count -gt 40) { Warn "... and $($all.Count - 40) more" }
    Warn 'the ignore rules above remove secrets, dependencies, and session backups from this list.'
    Ok 'run without -DryRun to perform it'
    exit $exitOk
  }
} else {
  & git -C $ProjectDir add -A | Out-Null
}
$staged = @(& git -C $ProjectDir diff --cached --name-only 2>$null)

if ($staged.Count -eq 0) {
  Ok 'nothing to commit (working tree clean)'
  Head 'Last 5 commits'
  & git -C $ProjectDir log --oneline -5
  exit $exitOk
}

$suspects = @($staged | Where-Object { $_ -and (Test-SecretPath -Path $_) })
if ($suspects.Count -gt 0) {
  Head 'Secret-looking files detected -- unstaging them'
  foreach ($s in $suspects) {
    Bad "  $s"
    if (-not $DryRun) { & git -C $ProjectDir reset -q -- $s | Out-Null }
  }
  Warn 'they stay on disk but will NOT be committed. Delete them or add them to .gitignore.'
}

$staged = @(& git -C $ProjectDir diff --cached --name-only 2>$null)
Head "Files to commit ($($staged.Count))"
$staged | Select-Object -First 40 | ForEach-Object { Write-Host "   $_" }
if ($staged.Count -gt 40) { Warn "... and $($staged.Count - 40) more" }

# Content scan: warn when a staged text file looks like it holds a credential.
$flagged = @()
foreach ($f in $staged) {
  $full = Join-Path $ProjectDir $f
  if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { continue }
  if ((Get-Item -LiteralPath $full).Length -gt 512KB) { continue }
  $hit = Select-String -LiteralPath $full -Pattern $SECRET_CONTENT_PATTERN -List -ErrorAction SilentlyContinue
  if ($hit) { $flagged += $f }
}
if ($flagged.Count -gt 0) {
  Head 'Possible credentials INSIDE these files -- review before publishing'
  $flagged | ForEach-Object { Warn "  $_" }
  Warn 'a public repository would expose them; rotate the credential if it is real.'
}

if (-not $Message) { $Message = 'backup ' + (Get-Date -Format 'yyyy-MM-dd HH:mm') }
if ($DryRun) { Ok "would commit with message: $Message"; exit $exitOk }

$commitOut = & git -C $ProjectDir commit -q -m $Message 2>&1
if ($LASTEXITCODE -ne 0) { Bad "commit failed"; $commitOut | ForEach-Object { Write-Host "   $_" }; exit $exitErr }
Ok "committed: $Message"

Head 'Remote'
$existingRemote = & git -C $ProjectDir remote get-url origin 2>$null
if ($Remote) {
  if ($existingRemote -and $existingRemote -ne $Remote) {
    & git -C $ProjectDir remote set-url origin $Remote | Out-Null
    Ok "origin updated: $Remote"
  } elseif (-not $existingRemote) {
    & git -C $ProjectDir remote add origin $Remote | Out-Null
    Ok "origin added: $Remote"
  } else {
    Ok "origin already correct: $Remote"
  }
} elseif ($existingRemote) {
  Ok "existing origin: $existingRemote"
} else {
  Warn 'no remote configured; pass -Remote <github-url> to enable pushing'
  Warn "add it later with: git -C `"$ProjectDir`" remote add origin <url>"
  exit $exitOk
}

if ($NoPush) { Warn 'push skipped (-NoPush)'; exit $exitOk }

$proxy = Get-LocalProxy
if ($proxy) { Ok "system proxy detected: $proxy" }

# Pre-flight: refuse to push when the remote has commits we do not have.
# Run quietly -- a missing remote branch is normal on the first push.
$fetchCode = Invoke-GitNet -Arguments @('fetch', '-q', 'origin', $Branch) -Proxy $proxy -Quiet
if ($fetchCode -ne 0 -and $proxy) { $fetchCode = Invoke-GitNet -Arguments @('fetch', '-q', 'origin', $Branch) -Quiet }
if ($fetchCode -eq 0) {
  $remoteRef = & git -C $ProjectDir rev-parse --verify -q "origin/$Branch" 2>$null
  if ($remoteRef) {
    # Unrelated histories: the remote root differs from ours (a repository
    # created with an auto README), so a plain push would be rejected.
    $mergeBase = & git -C $ProjectDir merge-base HEAD "origin/$Branch" 2>$null
    if (-not $mergeBase) {
      Head 'Unrelated histories detected'
      Warn "origin/$Branch comes from a different root (often GitHub's auto-generated README)."
      Warn 'rebasing your commit on top of it now...'
      $rebaseCode = Invoke-GitNet -Arguments @('pull', '--rebase', 'origin', $Branch, '--allow-unrelated-histories') -Proxy $proxy
      if ($rebaseCode -ne 0) {
        # The usual first-push conflict is add/add on README.md, where the remote
        # holds only GitHub's two-line stub. Resolve that narrow case
        # automatically; anything else stops and asks the operator.
        $conflicted = @(& git -C $ProjectDir diff --name-only --diff-filter=U 2>$null)
        $resolved = @()
        $blocked = @()
        foreach ($f in $conflicted) {
          if (-not $f) { continue }
          if ($f -notmatch '^README(\.md|\.txt|\.rst)?$') { $blocked += $f; continue }
          $path = Join-Path $ProjectDir $f
          if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { $blocked += $f; continue }

          # Read both sides straight out of the conflict markers. During a rebase
          # the "ours" section is the upstream (remote) version and "theirs" is
          # the commit being replayed, i.e. the local work.
          $lines = @(Get-Content -LiteralPath $path -Encoding UTF8)
          $iOur = -1; $iMid = -1; $iThe = -1; $iEnd = -1
          for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($iOur -lt 0 -and $lines[$i] -like '<<<<<<<*') { $iOur = $i }
            elseif ($iOur -ge 0 -and $iMid -lt 0 -and $lines[$i] -eq '=======') { $iMid = $i }
            elseif ($iMid -ge 0 -and $iThe -lt 0 -and $lines[$i] -like '>>>>>>>*') { $iThe = $i; $iEnd = $i; break }
          }
          if ($iOur -lt 0 -or $iMid -lt 0 -or $iThe -lt 0) { $blocked += $f; continue }

          $remoteSide = @($lines[($iOur + 1)..($iMid - 1)])
          $localSide  = @($lines[($iMid + 1)..($iThe - 1)])
          if ($localSide.Count -eq 0) { $blocked += $f; continue }
          # Only auto-resolve when the remote side is a short stub.
          if ($remoteSide.Count -gt 6 -and $remoteSide.Count -ge $localSide.Count) { $blocked += $f; continue }

          if (-not $DryRun) {
            $body = @()
            $body += $localSide
            if ($remoteSide.Count -gt 0) {
              Write-Lines -Path ($path + '.remote-stub.txt') -Lines $remoteSide
              $body += ''
              $body += '<!-- remote stub, merged automatically; safe to delete -->'
              $body += $remoteSide
            }
            Write-Lines -Path $path -Lines $body
            & git -C $ProjectDir add -- $f | Out-Null
          }
          $resolved += $f
        }
        if ($blocked.Count -eq 0 -and $resolved.Count -gt 0) {
          Head 'Auto-merged the remote README stub'
          $resolved | ForEach-Object { Ok "  kept your version of $_ (remote stub appended and saved as $_.remote-stub.txt)" }
          $contCode = Invoke-GitNet -Arguments @('-c', 'core.editor=true', 'rebase', '--continue') -Proxy $proxy
          if ($contCode -ne 0) {
            Bad 'the rebase still could not continue; resolve it by hand:'
            Bad "  git -C `"$ProjectDir`" status"
            exit $exitDiverged
          }
          Ok 'rebase complete'
        } else {
          Bad 'the rebase hit a conflict that needs a human decision:'
          foreach ($f in ($blocked + $resolved)) { Bad "  $f" }
          Bad 'resolve the files, then run:'
          Bad "  git -C `"$ProjectDir`" add <files>"
          Bad "  git -C `"$ProjectDir`" rebase --continue"
          Bad 'then re-run this script.'
          Bad "to give up instead: git -C `"$ProjectDir`" rebase --abort"
          exit $exitDiverged
        }
      } else {
        Ok 'rebase complete'
      }
    } else {
      $behind = & git -C $ProjectDir rev-list --count "HEAD..origin/$Branch" 2>$null
      if ($behind -and [int]$behind -gt 0) {
        Bad "origin/$Branch has $behind commit(s) you do not have; the push would be rejected."
        Warn "fix: git -C `"$ProjectDir`" pull --rebase origin $Branch"
        exit $exitDiverged
      }
    }
  }
} else {
  Warn "pre-flight fetch reported nothing to compare (normal for a brand-new remote); pushing"
}

Head 'Push'
$code = Invoke-GitNet -Arguments @('push', '-u', 'origin', $Branch) -Proxy $proxy
if ($code -ne 0 -and $proxy) {
  Warn "push through the proxy failed (exit $code); retrying directly"
  $code = Invoke-GitNet -Arguments @('push', '-u', 'origin', $Branch)
}
if ($code -ne 0) {
  Warn 'push failed, but the local commit is safe.'
  Warn 'common causes: not signed in to GitHub, no network, or the remote moved ahead.'
  if ($proxy) { Warn "a permanent fix: git config --global http.proxy $proxy" }
  exit $exitPushFail
}
Ok 'push complete'
Head 'Last 5 commits'
& git -C $ProjectDir log --oneline -5
exit $exitOk
