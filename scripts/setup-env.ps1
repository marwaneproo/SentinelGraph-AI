$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$envPath = Join-Path $projectRoot ".env"
$examplePath = Join-Path $projectRoot ".env.example"

if (-not (Test-Path $examplePath)) {
    throw "Missing .env.example. Restore the project configuration file and retry."
}


if (-not (Test-Path $envPath)) {
    Copy-Item $examplePath $envPath
}

function New-Secret([int]$byteCount) {
    $bytes = New-Object byte[] $byteCount
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    return ([BitConverter]::ToString($bytes) -replace "-", "").ToLowerInvariant()
}


$secretKeys = @(
    "NEO4J_PASSWORD",
    "JWT_SECRET",
    "SEED_ADMIN_PASSWORD",
    "SEED_ANALYST_PASSWORD",
    "SEED_VIEWER_PASSWORD"
)
$content = Get-Content -Path $envPath -Raw

foreach ($key in $secretKeys) {
    $pattern = "(?m)^$key=__GENERATE_ON_FIRST_START__$"
    if ($content -match $pattern) {
        $byteCount = if ($key -eq "JWT_SECRET") { 48 } else { 24 }
        $replacement = "$key=$(New-Secret $byteCount)"
        $content = [regex]::Replace($content, $pattern, $replacement)
    }
    elseif ($content -notmatch "(?m)^$key=.+$") {
        $byteCount = if ($key -eq "JWT_SECRET") { 48 } else { 24 }
        $content = $content.TrimEnd() + "`r`n$key=$(New-Secret $byteCount)`r`n"
    }
}

[System.IO.File]::WriteAllText(
    $envPath,
    $content,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host "Local .env is ready. Generated credentials stay in that ignored file."
