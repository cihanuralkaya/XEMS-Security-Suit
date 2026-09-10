# sign-dev.ps1 - Create a self-signed TEST cert and test-sign xemsflt.sys.
# DEVELOPMENT ONLY. Requires the target machine to have test-signing enabled
# (bcdedit /set testsigning on + reboot). NEVER ship a test-signed driver.
param([Parameter(Mandatory)][string]$SysPath)
$ErrorActionPreference = 'Stop'

$cn = 'XEMS Dev Test Cert'
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$cn" `
        -CertStoreLocation Cert:\CurrentUser\My -KeyUsage DigitalSignature `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3')   # EKU: code signing
$pwd = ConvertTo-SecureString 'devpass' -AsPlainText -Force
$pfx = Join-Path $PSScriptRoot 'xems-dev.pfx'
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $pwd | Out-Null

# signtool ships with the WDK/SDK.
& signtool sign /fd SHA256 /f $pfx /p 'devpass' `
    /tr http://timestamp.digicert.com /td SHA256 $SysPath
if ($LASTEXITCODE -ne 0) { throw "signtool failed" }
Write-Host "Test-signed: $SysPath"
Write-Host "To trust on this dev box, export the .cer and: certutil -addstore Root xems-dev.cer"
