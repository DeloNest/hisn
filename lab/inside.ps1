# Runs INSIDE Windows Sandbox only. Uses a standard user, because Hisn refuses to run elevated.
Start-Transcript C:\out\transcript.txt -Force
if ($env:USERNAME -ne 'WDAGUtilityAccount') { throw 'not in Windows Sandbox' }
New-Item -ItemType File C:/hisn-disposable-vm.marker -Force | Out-Null
New-Item -ItemType Directory C:\lab -Force | Out-Null
Copy-Item C:\bin\* C:\lab
$pw = 'T!' + [guid]::NewGuid().ToString('N').Substring(0,16)
$sec = ConvertTo-SecureString $pw -AsPlainText -Force
New-LocalUser tester -Password $sec | Out-Null
Add-LocalGroupMember -SID S-1-5-32-545 -Member tester -ErrorAction SilentlyContinue
$c = New-Object pscredential "$env:COMPUTERNAME\tester", $sec
New-Item -ItemType Directory C:\res -Force | Out-Null
icacls C:\res /grant 'tester:(OI)(CI)M' | Out-Null
$p = Start-Process cmd.exe -ArgumentList '/c set LOCALAPPDATA=C:\Users\tester\AppData\Local&set USERPROFILE=C:\Users\tester&whoami /all > C:\res\who.txt & C:\lab\hisn.exe selftest C:\lab\hisn-probe.exe > C:\res\selftest.txt 2>&1 & C:\lab\hisn.exe clean >> C:\res\selftest.txt 2>&1' -Credential $c -LoadUserProfile -WorkingDirectory C:\lab -PassThru
$p.WaitForExit(400000) | Out-Null
Copy-Item C:\res\* C:\out -Force
Stop-Transcript
'done' | Out-File C:\out\done.txt
