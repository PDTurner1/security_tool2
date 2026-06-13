# winrm_setup.ps1
# Run this ONCE on each Windows target, as Administrator.
# -------------------------------------------------------------

# 1. Enable PowerShell Remoting (starts WinRM, creates HTTP listener on 5985)
Enable-PSRemoting -Force

# 2. Allow connections from your Linux host (or use specific IPs for tighter control)
#    Replace * with your Ubuntu host IP for production use, e.g.:
#    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.1.10"
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# 3. (Recommended for production) Set up HTTPS listener on port 5986
#    Creates a self-signed cert — replace <HOSTNAME> with the machine's hostname or IP.
$hostname = $env:COMPUTERNAME
$cert = New-SelfSignedCertificate `
    -DnsName $hostname `
    -CertStoreLocation Cert:\LocalMachine\My `
    -NotAfter (Get-Date).AddYears(5)

New-Item -Path WSMan:\LocalHost\Listener `
    -Transport HTTPS `
    -Address * `
    -CertificateThumbprint $cert.Thumbprint `
    -Force

# Open firewall for WinRM HTTPS
New-NetFirewallRule `
    -DisplayName "WinRM HTTPS" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 5986 `
    -Action Allow

Write-Host ""
Write-Host "WinRM is configured. Certificate thumbprint: $($cert.Thumbprint)"
Write-Host "Test from Linux: python workstation_validator.py --host $hostname --user Administrator --https --no-verify-ssl"
