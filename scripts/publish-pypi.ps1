# publish-pypi.ps1 — MikrotikAPI-BF PyPI publisher
# Usage: .\scripts\publish-pypi.ps1 -Token "pypi-XXXXXXXXX"
#        .\scripts\publish-pypi.ps1  # reads PYPI_TOKEN env var

param(
    [string]$Token = $env:PYPI_TOKEN,
    [switch]$TestPyPI
)

$ErrorActionPreference = "Stop"
$repo = $PSScriptRoot | Split-Path

Set-Location $repo

Write-Host "=== MikrotikAPI-BF PyPI Publisher ==="

if (-not $Token) {
    Write-Error "No PyPI token. Set PYPI_TOKEN env var or pass -Token pypi-XXXX"
    exit 1
}

# Clean
Remove-Item -Recurse -Force dist, build, "*.egg-info" -ErrorAction SilentlyContinue

# Build
Write-Host "Building..."
python -m build
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed"; exit 1 }

# Check
Write-Host "Checking..."
python -m twine check dist/*

# Upload
$repo_url = if ($TestPyPI) { "https://test.pypi.org/legacy/" } else { "https://upload.pypi.org/legacy/" }
$target = if ($TestPyPI) { "TestPyPI" } else { "PyPI" }

Write-Host "Uploading to $target..."
$env:TWINE_USERNAME = "__token__"
$env:TWINE_PASSWORD = $Token

$twineArgs = @("upload", "dist/*", "--non-interactive")
if ($TestPyPI) { $twineArgs += "--repository-url", $repo_url }

python -m twine @twineArgs

if ($LASTEXITCODE -eq 0) {
    $ver = python -c "from version import __version__; print(__version__)"
    Write-Host "`n=== Published mikrotikapi-bf v$ver to $target ===`n"
    if (-not $TestPyPI) {
        Write-Host "Install: pip install mikrotikapi-bf==$ver"
        Write-Host "URL: https://pypi.org/project/mikrotikapi-bf/$ver/"
    }
} else {
    Write-Error "Upload failed"
    exit 1
}
