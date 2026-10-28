# Download dpiprobe reports into ..\reports.
# Token: CLOUDFLARE_API_TOKEN, or CLAUDEFLARE. Account: CLOUDFLARE_ACCOUNT_ID.
# The token is never printed.
$ErrorActionPreference = 'Stop'
$token = $env:CLOUDFLARE_API_TOKEN
if (-not $token) { $token = $env:CLAUDEFLARE }
if (-not $token) { Write-Error 'Set CLOUDFLARE_API_TOKEN'; exit 1 }
$account = $env:CLOUDFLARE_ACCOUNT_ID
if (-not $account) { Write-Error 'Set CLOUDFLARE_ACCOUNT_ID'; exit 1 }

$here = Split-Path -Parent $PSCommandPath
$root = Split-Path -Parent $here
$destRoot = Join-Path $root 'reports'
New-Item -ItemType Directory -Force -Path $destRoot | Out-Null
$H = @{ Authorization = "Bearer $token" }
$base = "https://api.cloudflare.com/client/v4/accounts/$account"

function Get-CF([string]$url) {
  try {
    return Invoke-WebRequest -Headers $H -Uri $url -UseBasicParsing -TimeoutSec 60
  } catch {
    $code = 0
    if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    throw "cloudflare http $code"
  }
}

$keys = New-Object System.Collections.Generic.List[string]
$mode = 'kv'
$ns = ''
try {
  $r = Get-CF "$base/r2/buckets/dpiprobe-reports/objects"
  $j = $r.Content | ConvertFrom-Json
  $mode = 'r2'
  $objs = @()
  if ($j.result.objects) { $objs = @($j.result.objects) }
  elseif ($j.objects) { $objs = @($j.objects) }
  elseif ($j.result) { $objs = @($j.result) }
  foreach ($o in $objs) {
    if ($o.key) { $keys.Add([string]$o.key) }
  }
} catch {
  $mode = 'kv'
}

if ($mode -eq 'kv') {
  $r = Get-CF "$base/storage/kv/namespaces"
  $j = $r.Content | ConvertFrom-Json
  foreach ($n in @($j.result)) {
    if ($n.title -eq 'dpiprobe-reports') { $ns = [string]$n.id }
  }
  if (-not $ns) { Write-Error 'namespace dpiprobe-reports not found'; exit 1 }
  $cursor = ''
  do {
    $url = "$base/storage/kv/namespaces/$ns/keys?prefix=rep:&limit=1000"
    if ($cursor) { $url = $url + "&cursor=$([uri]::EscapeDataString($cursor))" }
    $r = Get-CF $url
    $j = $r.Content | ConvertFrom-Json
    foreach ($item in @($j.result)) {
      if ($item.name) { $keys.Add([string]$item.name) }
    }
    $cursor = [string]$j.result_info.cursor
  } while ($cursor)
}

$saved = 0
foreach ($key in $keys) {
  $rel = [string]$key
  if ($rel.StartsWith('rep:')) { $rel = $rel.Substring(4) }
  $rel = $rel -replace '\\','/'
  if ($rel -match '\.\.' -or $rel.StartsWith('/') -or $rel -match '^[A-Za-z]:') { continue }
  $out = Join-Path $destRoot ($rel -replace '/','\')
  $parent = Split-Path -Parent $out
  if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
  if (Test-Path $out) { continue }
  if ($mode -eq 'r2') {
    $parts = $rel.Split('/')
    $enc = @()
    foreach ($p in $parts) { $enc += [uri]::EscapeDataString($p) }
    $url = "$base/r2/buckets/dpiprobe-reports/objects/$($enc -join '/')"
  } else {
    $url = "$base/storage/kv/namespaces/$ns/values/$([uri]::EscapeDataString($key))"
  }
  $resp = Get-CF $url
  [System.IO.File]::WriteAllText($out, $resp.Content)
  $saved++
  Write-Output $rel
}
Write-Output "saved $saved"
