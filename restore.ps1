param(
  [Parameter(Mandatory=$true)][string]$DshHome,
  [Parameter(Mandatory=$true)][string]$Profile,
  [string]$Node,
  [string]$State,
  [switch]$Apply
)
$ErrorActionPreference = 'Stop'
if ($Apply -and (Get-Process -Name 'DeepSeek Harness','dsh' -ErrorAction SilentlyContinue)) {
  throw 'Close DSH completely before applying changes. Use an external PowerShell window.'
}
if (!$Node) {
  $Node = Join-Path $env:USERPROFILE '.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe'
}
if (!(Test-Path -LiteralPath $Node -PathType Leaf) -or [IO.Path]::GetFileName($Node) -ne 'node.exe') {
  throw 'Pass the absolute path to Node.js 24.9+ using -Node.'
}
if ($env:NODE_OPTIONS -or $env:NODE_PATH) { throw 'Clear NODE_OPTIONS and NODE_PATH in this shell before continuing.' }
$v = & $Node --version
if ($LASTEXITCODE -or $v -notmatch '^v(\d+)\.(\d+)\.') { throw 'Could not verify Node.js version.' }
if (([int]$Matches[1] -lt 24) -or (([int]$Matches[1] -eq 24) -and ([int]$Matches[2] -lt 9))) { throw 'Node.js >=24.9 is required.' }
$cli = Join-Path $PSScriptRoot 'maintenance.mjs'
$cliArgs = @('restore', '--home', $DshHome, '--profile', $Profile)
if ($State) { $cliArgs += @('--state', $State) }
if ($Apply) { $cliArgs += '--apply' }
& $Node $cli @cliArgs
if ($LASTEXITCODE -ne 0) { throw ('Maintenance failed (exit ' + $LASTEXITCODE + '). Review the output before retrying.') }
