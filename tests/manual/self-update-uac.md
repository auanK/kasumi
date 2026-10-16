# Windows self-update administrator permission smoke test

This tests the current updater even when the development build is newer than
the published release. There is no public force/downgrade switch. Build a
disposable executable reporting `0.0.0`, then let its normal updater install the
release selected from GitHub. Version, official-source, checksum, package, and
installer-handoff checks remain enabled. Never use this test executable with
real profiles or put it on `PATH`.

Automated tests cover ACL shape, file identity, rollback, and Unicode handoff.
Protected-directory permission denial and administrator installation require manual verification.

## 1. Build a disposable executable

Use Windows PowerShell from the repository root, with the
[build prerequisites](../../docs/build-and-test.md#prerequisites) and Visual Studio
2022 C++ tools installed. Keep this PowerShell session open for the later steps.

The CMake project-include hook changes version metadata only in this separate
build, including the Windows version resource. It does not edit repository
sources or the normal build directory. Choose a short writable test root if
your temporary-directory path is too long.

```powershell
$testRoot = Join-Path $env:TEMP ("kasumi-update-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot -ErrorAction Stop | Out-Null
$versionHook = Join-Path $testRoot 'test-version.cmake'
@'
set(PROJECT_VERSION "0.0.0")
set(PROJECT_VERSION_MAJOR 0)
set(PROJECT_VERSION_MINOR 0)
set(PROJECT_VERSION_PATCH 0)
'@ | Set-Content -LiteralPath $versionHook -Encoding ascii

cmake -S . -B "$testRoot/build" -G "Visual Studio 17 2022" -A x64 `
    "-DCMAKE_PROJECT_kasumi_INCLUDE=$($versionHook.Replace('\', '/'))" `
    -DBUILD_TESTING=OFF
if ($LASTEXITCODE -ne 0) { throw 'Test configuration failed.' }
cmake --build "$testRoot/build" --config Release --target kasumi --parallel
if ($LASTEXITCODE -ne 0) { throw 'Test build failed.' }

$testExe = Join-Path $testRoot 'kasumi.exe'
Copy-Item -LiteralPath "$testRoot/build/Release/kasumi.exe" -Destination $testExe -ErrorAction Stop
$testVersion = & $testExe --version
if ($LASTEXITCODE -ne 0 -or $testVersion -ne 'kasumi version 0.0.0') {
    throw 'The disposable executable must report version 0.0.0.'
}
$beforeHash = (Get-FileHash -LiteralPath $testExe -Algorithm SHA256).Hash
Write-Host "Disposable executable: $testExe"
Write-Host "Unchanged test build: $testRoot/build/Release/kasumi.exe"
```

Keep `build/Release/kasumi.exe` unchanged as the original test copy for repeats.
The updater must run on the copied `$testExe`, not on the build output or your
normal installation.


## 2. Prepare a protected installation (administrator)

Reuse the unchanged `build/Release/kasumi.exe` from step 1. If a writable copy
already updated successfully, do not use that updated copy: it now reports the
published version and may correctly skip another update. No recompilation is
needed while the original build still reports `0.0.0`.

Record the unchanged build's absolute path. Open a separate PowerShell window
with **Run as administrator**, then execute the following block. Paste paths
without surrounding quotes when prompted. This creates a new test directory;
its ACL grants full control to SYSTEM/Administrators and read/execute to Users.
Numeric SIDs work across Windows display languages. The resets prevent a copied
file's earlier permissions from giving the test user write access.

```powershell
$buildExe = Read-Host 'Absolute path of the unchanged build/Release/kasumi.exe'
$version = & $buildExe --version
if ($LASTEXITCODE -ne 0 -or $version -ne 'kasumi version 0.0.0') {
    throw 'Use the unchanged 0.0.0 test build.'
}
$uacDir = Join-Path $env:ProgramFiles ("KasumiUpdaterUac-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $uacDir -ErrorAction Stop | Out-Null
icacls.exe $uacDir /reset
if ($LASTEXITCODE -ne 0) { throw 'Could not reset test-directory permissions.' }
icacls.exe $uacDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX'
if ($LASTEXITCODE -ne 0) { throw 'Could not protect the test directory.' }
$uacExe = Join-Path $uacDir 'kasumi.exe'
Copy-Item -LiteralPath $buildExe -Destination $uacExe -ErrorAction Stop
icacls.exe $uacExe /reset
if ($LASTEXITCODE -ne 0) { throw 'Could not reset test-executable permissions.' }
Write-Host "Protected executable: $uacExe"
```

Copy the printed protected executable path and close this elevated window.
Do not change permissions on Program Files itself or on a real installation.

## 3. Attempt update from a non-elevated session

From the **non-elevated** PowerShell session, attempt the update on the protected executable:

```powershell
$uacExe = Read-Host 'Protected executable path printed by the administrator'
$version = & $uacExe --version
if ($LASTEXITCODE -ne 0 -or $version -ne 'kasumi version 0.0.0') {
    throw 'The protected test copy must report 0.0.0.'
}
$uacBeforeHash = (Get-FileHash -LiteralPath $uacExe -Algorithm SHA256).Hash
& $uacExe --lang en update
```

The updater detects that the installation directory requires administrator privileges and cancels immediately with:
`Update failed: Administrator privileges required. Run as administrator to update.`

Verify that the executable was not altered:

```powershell
& $uacExe --version
if ((Get-FileHash -LiteralPath $uacExe -Algorithm SHA256).Hash -ne $uacBeforeHash) {
    throw 'Non-elevated attempt altered the executable.'
}
```

Pass: the updater refused to proceed without sufficient privileges, reported the clear administrator requirement, and left the executable intact.

## 4. Run update from an elevated administrator session

In an **elevated** (Run as administrator) PowerShell session, run the update on the protected copy:

```powershell
$uacExe = Read-Host 'Protected executable path'
& $uacExe --lang en update
```

Wait for the helper's completion message before checking the protected copy:

```powershell
& $uacExe --version
if ((Get-FileHash -LiteralPath $uacExe -Algorithm SHA256).Hash -eq $uacBeforeHash) {
    throw 'The executable was not replaced.'
}
$backups = @(Get-ChildItem -LiteralPath (Split-Path -Parent $uacExe) -File -Filter '*.kasumi-previous-*')
if ($backups.Count -ne 1) { throw 'Expected one recovery copy in this fresh test directory.' }
if ((Get-FileHash -LiteralPath $backups[0].FullName -Algorithm SHA256).Hash -ne $uacBeforeHash) {
    throw 'Recovery-copy hash differs from the original test executable.'
}
```

Pass: running with administrator privileges allowed the updater to complete the installation directly, replace the executable, and keep a backup recovery copy.
