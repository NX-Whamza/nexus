# NEXUS - Build & Deploy Script
# Combines package creation and VM transfer into a single workflow.

$vmUser = if ($env:NOC_VM_USER) { $env:NOC_VM_USER } else { "CHANGE_ME" }
$vmIP = if ($env:NOC_VM_IP) { $env:NOC_VM_IP } else { "CHANGE_ME" }
$vmPath = "/home/$vmUser"
$sshKeyPath = "$env:USERPROFILE\.ssh\id_rsa_noc_vm"
$sshTarget = "{0}@{1}" -f $vmUser, $vmIP

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "NEXUS - Build & Deploy" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# ----------------------------------------------------------------
# PHASE 1: BUILD PACKAGE
# ----------------------------------------------------------------
Write-Host "[1/2] Building Deployment Package..." -ForegroundColor Yellow

$projectRoot = $PSScriptRoot
if (-not $projectRoot) { $projectRoot = Get-Location }

$vmDeploymentPath = Join-Path $projectRoot "vm_deployment"
if (-not (Test-Path $vmDeploymentPath)) {
    Write-Host "[ERROR] vm_deployment directory not found!" -ForegroundColor Red
    exit 1
}

$includeItems = @(
    "api_server.py",
    "launcher.py",
    "nexus.html",
    "login.html",
    "change-password.html",
    "requirements.txt",
    "README.txt",
    "config_policies",
    "ros-migration-trainer-v3",
    "docs",
    "nextlink_compliance_reference.py",
    "nextlink_enterprise_reference.py",
    "nextlink_standards.py",
    "nexus.service",
    "setup_vm.sh",
    "configure_nginx_domain.sh",
    "fix_nginx_now.sh",
    "fix_nginx_simple.sh",
    "setup_https_godaddy.sh",
    "setup_godaddy_ssl.sh",
    "check_dns.sh",
    "QUICK_EXTRACT.sh"
)

$tempDir = Join-Path $projectRoot "vm_migration_temp"
if (Test-Path $tempDir) { Remove-Item -Path $tempDir -Recurse -Force }
New-Item -ItemType Directory -Path $tempDir | Out-Null

foreach ($item in $includeItems) {
    $sourcePath = Join-Path $vmDeploymentPath $item
    $destPath = Join-Path $tempDir $item
    if (Test-Path $sourcePath) {
        if (Test-Path $sourcePath -PathType Container) {
            Copy-Item -Path $sourcePath -Destination $destPath -Recurse -Force
            Write-Host "  [OK] Copied directory: $item" -ForegroundColor Gray
        } else {
            Copy-Item -Path $sourcePath -Destination $destPath -Force
            Write-Host "  [OK] Copied file: $item" -ForegroundColor Gray
        }
    } else {
        Write-Host "  [WARN] $item not found in vm_deployment/" -ForegroundColor Yellow
    }
}

$envTemplate = @'
# Copy to .env (optional). SMTP/email is not used.
ADMIN_EMAILS=netops@team.nxlink.com,whamza@team.nxlink.com
# JWT_SECRET=your-secret-here
# NEXTLINK_SSH_USERNAME=
# NEXTLINK_SSH_PASSWORD=
'@
$envTemplate | Out-File -FilePath (Join-Path $tempDir ".env.template") -Encoding UTF8

$archiveName = "nexus-vm-$(Get-Date -Format 'yyyyMMdd-HHmmss').tar.gz"
$archivePath = Join-Path $projectRoot $archiveName

if (Get-Command tar -ErrorAction SilentlyContinue) {
    Push-Location $tempDir
    & tar -czf $archivePath * | Out-Null
    Pop-Location
} else {
    Write-Host "[WARN] tar not available on this system. Falling back to ZIP." -ForegroundColor Yellow
    $archiveName = $archiveName -replace "\.tar\.gz$", ".zip"
    $archivePath = Join-Path $projectRoot $archiveName
    Compress-Archive -Path (Join-Path $tempDir '*') -DestinationPath $archivePath -Force
}

Remove-Item $tempDir -Recurse -Force
Write-Host "[SUCCESS] Package Created: $archiveName" -ForegroundColor Green

# ----------------------------------------------------------------
# PHASE 2: DEPLOY PACKAGE
# ----------------------------------------------------------------
Write-Host ""
Write-Host "[2/2] Deploying to VM ($vmIP)..." -ForegroundColor Yellow

$sshBaseArgs = @("-o", "StrictHostKeyChecking=no")
if ($sshKeyPath -and (Test-Path $sshKeyPath)) {
    $sshBaseArgs += "-i"
    $sshBaseArgs += $sshKeyPath
} else {
    Write-Host "[WARN] SSH key not found. You will be prompted for a password." -ForegroundColor Yellow
}

$scpArgs = $sshBaseArgs + @($archivePath, "$($sshTarget):$($vmPath)/vm_deployment/")
$result = & scp @scpArgs 2>&1
$scpExit = $LASTEXITCODE

if ($scpExit -eq 0) {
    Write-Host "[SUCCESS] Deployment Successful!" -ForegroundColor Green
    Write-Host ""
    Write-Host "NEXT STEPS ON VM:" -ForegroundColor Cyan
    Write-Host "1. ssh $vmUser@$vmIP" -ForegroundColor White
    Write-Host "2. cd ~/vm_deployment" -ForegroundColor White
    Write-Host "3. Extract the archive:" -ForegroundColor White
    Write-Host "   tar -xzf nexus-vm-*.tar.gz" -ForegroundColor Gray
    Write-Host "4. Make scripts executable:" -ForegroundColor White
    Write-Host "   chmod +x *.sh" -ForegroundColor Gray
    Write-Host "5. Run fix script:" -ForegroundColor White
    Write-Host "   bash fix_nginx_simple.sh" -ForegroundColor Gray
    Write-Host ""
    Write-Host "The archive is now in ~/vm_deployment/ directory!" -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "[ERROR] Transfer Failed!" -ForegroundColor Red
    Write-Host $result -ForegroundColor Gray
}
