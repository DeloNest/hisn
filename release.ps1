# Builds, signs and publishes a release:  .\release.ps1 0.2.1 "What changed"
# The signing key stays outside the repository. Losing it means existing installs can no longer update.
param([Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version, [Parameter(Mandatory)][string]$Notes, [string]$Repo = 'DeloNest/hisn', [switch]$BuildOnly)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$key = "$env:USERPROFILE\.tauri\hisn.key"
if (-not (Test-Path $key)) { throw "signing key not found: $key" }
$conf = Get-Content "$root\app\tauri.conf.json" -Raw | ConvertFrom-Json
if ($conf.version -ne $Version) { throw "set version $Version in app/tauri.conf.json first (now $($conf.version))" }
if (-not $BuildOnly) {
    if (git -C $root status --porcelain) { throw 'commit your changes first' }
    git -C $root fetch -q origin
    if ((git -C $root rev-parse HEAD) -ne (git -C $root rev-parse origin/main)) { throw 'push main first' }
}
$env:CARGO_TARGET_DIR = "$env:USERPROFILE\hisn-build\rel"
$env:RUSTFLAGS = "-C target-feature=+crt-static --remap-path-prefix=$env:USERPROFILE\.cargo=cargo --remap-path-prefix=$root=src --remap-path-prefix=$env:USERPROFILE=home"
$env:TAURI_SIGNING_PRIVATE_KEY = Get-Content $key -Raw
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = ''
Push-Location "$root\app"
try { cmd /c 'npx --yes @tauri-apps/cli@2 build 2>&1'; if ($LASTEXITCODE) { throw 'build failed' } }
finally { Pop-Location; Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY, Env:RUSTFLAGS, Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue }
$dir = "$env:USERPROFILE\hisn-build\rel\release\bundle\nsis"
$exe = "Hisn_${Version}_x64-setup.exe"
$json = [ordered]@{ version = $Version; notes = $Notes; pub_date = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    platforms = @{ 'windows-x86_64' = @{ signature = (Get-Content "$dir\$exe.sig" -Raw).Trim(); url = "https://github.com/$Repo/releases/download/v$Version/$exe" } } } | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText("$dir\latest.json", $json)
[IO.File]::WriteAllText("$dir\SHA256SUMS.txt", "$((Get-FileHash "$dir\$exe").Hash.ToLower()) *$exe`n")
if ($BuildOnly) { "built: $dir"; return }
gh release create "v$Version" "$dir\$exe" "$dir\$exe.sig" "$dir\latest.json" "$dir\SHA256SUMS.txt" -R $Repo --target main --latest --title "Hisn $Version" --notes $Notes
if ($LASTEXITCODE) { throw 'publishing failed' }
