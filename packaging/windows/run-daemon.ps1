$ErrorActionPreference = 'Stop'
$base = Split-Path -Parent $MyInvocation.MyCommand.Path
$secure = Import-Clixml (Join-Path $base 'passphrase.dpapi.xml')
if ($secure -isnot [System.Security.SecureString]) { throw 'Expected a DPAPI-protected SecureString' }
$credential = New-Object System.Management.Automation.PSCredential('bunker', $secure)
try {
    $env:BUNKER_PASSPHRASE = $credential.GetNetworkCredential().Password
    & (Join-Path $base 'bunker.exe') daemon --repo (Join-Path $base 'repository') --workspace 'C:\Workspaces\REPLACE'
    if ($LASTEXITCODE -ne 0) { throw 'Bunker daemon failed' }
} finally {
    Remove-Item Env:BUNKER_PASSPHRASE -ErrorAction SilentlyContinue
    $secure.Dispose()
}
