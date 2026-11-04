# Windows release bootstrap. Python 3 is required; no service installation occurs.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Version,
    [string]$Prefix = (Join-Path $HOME '.local'),
    [string]$ReleaseBase = '',
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '\A\d+\.\d+\.\d+(-[A-Za-z0-9.-]+)?\z') {
    throw 'Version must be an explicit release version without the v prefix'
}
if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows) -and
    [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') {
    throw 'Only Windows x64 releases are available'
}
$name = "bunker-$Version-x86_64-pc-windows-msvc.zip"
if (!$ReleaseBase) { $ReleaseBase = "https://github.com/jusso-dev/bunker/releases/download/v$Version" }
$temporary = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
[System.IO.Directory]::CreateDirectory($temporary) | Out-Null
try {
    foreach ($file in @($name, "$name.sha256")) {
        $destination = Join-Path $temporary $file
        if (Test-Path -LiteralPath $ReleaseBase -PathType Container) {
            Copy-Item -LiteralPath (Join-Path $ReleaseBase $file) -Destination $destination
        } else {
            if ($ReleaseBase -notmatch '^https://') { throw 'ReleaseBase must use HTTPS or be a local fixture directory' }
            Invoke-WebRequest -UseBasicParsing -Uri "$($ReleaseBase.TrimEnd('/'))/$file" -OutFile $destination
        }
    }
    $archive = Join-Path $temporary $name
    $sum = [System.IO.File]::ReadAllText("$archive.sha256")
    if ($sum -cnotmatch ('\A([0-9a-fA-F]{64})  ' + [regex]::Escape($name) + '\r?\n?\z')) {
        throw 'Invalid release checksum or archive filename'
    }
    $digest = $Matches[1].ToLowerInvariant()
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) {
        throw 'Archive checksum mismatch'
    }
    if (Get-Command gh -ErrorAction SilentlyContinue) {
        # Bind provenance to the release tag and packaging workflow, not just the repository.
        & gh attestation verify $archive --repo jusso-dev/bunker `
            --signer-workflow jusso-dev/bunker/.github/workflows/packages.yml `
            --source-ref "refs/tags/v$Version"
        if ($LASTEXITCODE -ne 0) { throw 'Release attestation verification failed' }
    } else {
        Write-Warning 'gh unavailable: verified SHA-256 only; release provenance was not verified.'
    }
    # Extract just the bounded installer member, never archive-supplied paths.
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($archive)
    try {
        $entries = @($zip.Entries | Where-Object { $_.FullName -ceq 'install.py' })
        if ($entries.Count -ne 1 -or $entries[0].Length -gt 65536 -or
            (($entries[0].ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000) {
            throw 'Archive must contain one regular install.py'
        }
        $script = Join-Path $temporary 'install.py'
        $inputStream = $entries[0].Open()
        $outputStream = [System.IO.File]::Create($script)
        try { $inputStream.CopyTo($outputStream) }
        finally { $inputStream.Dispose(); $outputStream.Dispose() }
    } finally { $zip.Dispose() }
    & $Python $script --archive $archive --sha256 $digest --prefix $Prefix
    if ($LASTEXITCODE -ne 0) { throw 'Release installation failed' }
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
