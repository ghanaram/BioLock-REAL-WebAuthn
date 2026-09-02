$TaskName = "BioLock Interactive Lock"
$ScriptPath = Join-Path $PSScriptRoot "lock-helper.ps1"

# Current logged-in Windows user
$User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

Write-Host "================================="
Write-Host "BIOLOCK INTERACTIVE LOCK INSTALL"
Write-Host "================================="
Write-Host "User   : $User"
Write-Host "Script : $ScriptPath"

# Remove old task if present
schtasks.exe /delete /tn $TaskName /f 2>$null

# Create task for the current interactive user.
# It is triggered manually by the BioLock Agent.
$Action = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""

schtasks.exe /create `
  /tn $TaskName `
  /tr $Action `
  /sc ONCE `
  /st 00:00 `
  /ru $User `
  /it `
  /f

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "✅ BioLock interactive lock task installed."
    Write-Host "Task: $TaskName"
} else {
    Write-Host ""
    Write-Host "❌ Failed to create task."
    exit 1
}
