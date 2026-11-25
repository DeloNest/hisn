# Runs the escape tests in a disposable Windows Sandbox. Never run hisn-probe on a gaming PC directly.
$ErrorActionPreference = 'Stop'
$build = Join-Path $env:USERPROFILE 'hisn-build'
$bin = "$build\lab\bin"; $out = "$build\lab\out"
New-Item -ItemType Directory -Force $bin, $out | Out-Null
Get-ChildItem $out -File | Remove-Item
Copy-Item "$build\release\hisn.exe", "$build\release\hisn-probe.exe", "$PSScriptRoot\inside.ps1" $bin -Force
@"
<Configuration><VGpu>Disable</VGpu><ClipboardRedirection>Disable</ClipboardRedirection><AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput><Networking>Enable</Networking>
<MappedFolders>
<MappedFolder><HostFolder>$bin</HostFolder><SandboxFolder>C:\bin</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
<MappedFolder><HostFolder>$out</HostFolder><SandboxFolder>C:\out</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
</MappedFolders>
<LogonCommand><Command>powershell.exe -ExecutionPolicy Bypass -File C:\bin\inside.ps1</Command></LogonCommand></Configuration>
"@ | Out-File "$build\lab\test.wsb" -Encoding utf8
Start-Process "$env:windir\System32\WindowsSandbox.exe" "`"$build\lab\test.wsb`""
"results will appear in $out"
