# Name: install-python-3.12.ps1
# Purpose: Installs Python 3.12.x on Windows without removing existing versions (e.g. 3.13.x)

$pythonVersion = "3.12.2"
$installerUrl = "https://www.python.org/ftp/python/$pythonVersion/python-$pythonVersion-amd64.exe"
$installerPath = "$env:TEMP\python-$pythonVersion-installer.exe"
$installDir = "C:\Python$($pythonVersion -replace '\.', '')"

Write-Host "[*] Downloading Python $pythonVersion installer..."
Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath

Write-Host "[*] Installing Python $pythonVersion to $installDir..."
Start-Process -FilePath $installerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=0 TargetDir=$installDir" -Wait

if (!(Test-Path "$installDir\python.exe")) {
    Write-Error "[✘] Installation failed or Python executable not found."
    Exit 1
}

Write-Host "[*] Setting environment variables for Python $pythonVersion..."
[System.Environment]::SetEnvironmentVariable("Path", "$installDir;$installDir\Scripts;" + [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine), [System.EnvironmentVariableTarget]::Machine)

Write-Host "[*] Verifying Python installation..."
& "$installDir\python.exe" --version
& "$installDir\python.exe" -m pip --version

Write-Host "`n[✔] Python $pythonVersion installed successfully at $installDir."
Write-Host "ℹ️  Restart your terminal or computer to apply environment changes."
