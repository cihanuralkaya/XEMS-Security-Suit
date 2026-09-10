# build.ps1 - Build xemsflt.sys with the WDK or EWDK. DEV path only.
# Prereq: EWDK ISO mounted (LaunchBuildEnv.cmd) OR Visual Studio + "Windows Driver Kit".
# msbuild must be on PATH (EWDK sets it up; VS: "Developer Command Prompt").
param(
    [ValidateSet('Debug','Release')] [string]$Config = 'Release',
    [string]$Platform = 'x64',
    [switch]$TestSign        # chain sign-dev.ps1 after a successful build
)
$ErrorActionPreference = 'Stop'
$proj = Join-Path $PSScriptRoot 'xemsflt.vcxproj'

& msbuild $proj /t:Build /p:Configuration=$Config /p:Platform=$Platform /m
if ($LASTEXITCODE -ne 0) { throw "msbuild failed ($LASTEXITCODE)" }

$sys = Join-Path $PSScriptRoot "$Platform\$Config\xemsflt.sys"
if (-not (Test-Path $sys)) { throw "xemsflt.sys not produced at $sys" }
Write-Host "Built: $sys"

if ($TestSign) { & (Join-Path $PSScriptRoot 'sign-dev.ps1') -SysPath $sys }
