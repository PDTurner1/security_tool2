# winrm_teardown.ps1
# Undoes everything applied by winrm_setup.ps1
# Run as Administrator on the Windows target.
# -------------------------------------------------------------

Write-Host ""
Write-Host "=== WinRM Teardown ===" -ForegroundColor Cyan
Write-Host "This will undo all WinRM configuration applied by winrm_setup.ps1"
Write-Host ""

# -------------------------------------------------------------
# Step 1 — Remove the HTTPS listener on port 5986
# -------------------------------------------------------------
Write-Host "[1] Removing HTTPS WinRM listener..." -ForegroundColor Yellow

$httpsListeners = Get-ChildItem WSMan:\LocalHost\Listener |
    Where-Object {
        (Get-Item "$($_.PSPath)\Transport").Value -eq "HTTPS"
    }

if ($httpsListeners) {
    foreach ($listener in $httpsListeners) {
        Remove-Item -Path $listener.PSPath -Recurse -Force
        Write-Host "    Removed listener: $($listener.PSPath)" -ForegroundColor Green
    }
} else {
    Write-Host "    No HTTPS listener found — skipping." -ForegroundColor Gray
}

# -------------------------------------------------------------
# Step 2 — Remove the WinRM HTTPS firewall rule
# -------------------------------------------------------------
Write-Host "[2] Removing WinRM HTTPS firewall rule..." -ForegroundColor Yellow

$fwRule = Get-NetFirewallRule -DisplayName "WinRM HTTPS" -ErrorAction SilentlyContinue
if ($fwRule) {
    Remove-NetFirewallRule -DisplayName "WinRM HTTPS"
    Write-Host "    Firewall rule 'WinRM HTTPS' removed." -ForegroundColor Green
} else {
    Write-Host "    Firewall rule 'WinRM HTTPS' not found — skipping." -ForegroundColor Gray
}

# -------------------------------------------------------------
# Step 3 — Remove the self-signed certificate created by the setup script
# -------------------------------------------------------------
Write-Host "[3] Removing self-signed WinRM certificate..." -ForegroundColor Yellow

$hostname = $env:COMPUTERNAME

# Find certs in LocalMachine\My that were issued to this machine's hostname
# and are self-signed (Issuer matches Subject)
$certs = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object {
        $_.Subject -match $hostname -and $_.Issuer -eq $_.Subject
    }

if ($certs) {
    foreach ($cert in $certs) {
        Remove-Item -Path "Cert:\LocalMachine\My\$($cert.Thumbprint)" -Force
        Write-Host "    Removed cert: $($cert.Thumbprint) (Subject: $($cert.Subject))" -ForegroundColor Green
    }
} else {
    Write-Host "    No matching self-signed certificate found — skipping." -ForegroundColor Gray
}

# -------------------------------------------------------------
# Step 4 — Reset TrustedHosts back to empty (was set to "*")
# -------------------------------------------------------------
Write-Host "[4] Clearing WinRM TrustedHosts..." -ForegroundColor Yellow

$current = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value
if ($current -ne "") {
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "" -Force
    Write-Host "    TrustedHosts cleared (was: $current)." -ForegroundColor Green
} else {
    Write-Host "    TrustedHosts already empty — skipping." -ForegroundColor Gray
}

# -------------------------------------------------------------
# Step 5 — Disable PowerShell Remoting and stop WinRM service
# -------------------------------------------------------------
Write-Host "[5] Disabling PowerShell Remoting..." -ForegroundColor Yellow

# Disable-PSRemoting removes the listener registrations and sets the
# LocalAccountTokenFilterPolicy back, but does not stop the service.
Disable-PSRemoting -Force

# Stop and disable the WinRM service entirely
Stop-Service WinRM -Force
Set-Service WinRM -StartupType Disabled

Write-Host "    PSRemoting disabled. WinRM service stopped and set to Disabled." -ForegroundColor Green

# -------------------------------------------------------------
# Step 6 — Remove the HTTP listener on port 5985 if it still exists
# -------------------------------------------------------------
Write-Host "[6] Removing HTTP WinRM listener (port 5985)..." -ForegroundColor Yellow

$httpListeners = Get-ChildItem WSMan:\LocalHost\Listener -ErrorAction SilentlyContinue |
    Where-Object {
        (Get-Item "$($_.PSPath)\Transport" -ErrorAction SilentlyContinue).Value -eq "HTTP"
    }

if ($httpListeners) {
    foreach ($listener in $httpListeners) {
        Remove-Item -Path $listener.PSPath -Recurse -Force
        Write-Host "    Removed HTTP listener: $($listener.PSPath)" -ForegroundColor Green
    }
} else {
    Write-Host "    No HTTP listener found — skipping." -ForegroundColor Gray
}

# -------------------------------------------------------------
# Summary
# -------------------------------------------------------------
Write-Host ""
Write-Host "=== Teardown Complete ===" -ForegroundColor Cyan
Write-Host "The following have been undone:"
Write-Host "  - HTTPS WinRM listener (port 5986) removed"
Write-Host "  - HTTP WinRM listener  (port 5985) removed"
Write-Host "  - Firewall rule 'WinRM HTTPS' removed"
Write-Host "  - Self-signed certificate removed from LocalMachine\My"
Write-Host "  - TrustedHosts reset to empty"
Write-Host "  - PowerShell Remoting disabled"
Write-Host "  - WinRM service stopped and set to Disabled"
Write-Host ""
Write-Host "To verify WinRM is fully off, run:" -ForegroundColor Yellow
Write-Host "  Get-Service WinRM"
Write-Host "  winrm enumerate winrm/config/listener"
Write-Host ""
