# Build and Test

## Prerequisites

Building Kasumi requires CMake 3.28+, Git, and a C++23 compiler:
* **C++23 Compiler**: A compiler supporting the C++23 features used by the codebase.
* **CMake**: Version 3.28 or later.
* **Git**: Used for dependency retrieval during the build.
* **Ninja**: The provided CMake presets use Ninja.
* **Python 3**: Required to generate the embedded locale header and run repository scripts.
* **rclone**: Required for rclone-backed remote operation and for system tests that exercise the rclone transport. Not required for building or running local transport tests.

Repository CI exercises:
* Visual Studio 2022 / MSVC on Windows (Debug and Release);
* GCC from the Windows MSYS2 UCRT64 environment (Debug and Release; tools verified under `/ucrt64/bin`);
* Clang from the Windows MSYS2 CLANG64 environment (Debug and Release; tools verified under `/clang64/bin`);
* GCC 14 on Ubuntu (Debug and Release);
* Clang on Ubuntu (Debug and Release).

This lists workflow coverage, not the result for an arbitrary commit. Consult
the Actions runs for the exact revision; provider-specific operational checks
can be run with the procedure in [Provider Certification](provider-certification.md).

### Windows Long Paths

CMake embeds `src/platform/windows/long_path_aware.manifest` into the CLI and
Windows test executables. Its `longPathAware` declaration opts the process in;
the host must also permit long Win32 paths through `LongPathsEnabled`. A source
path can fit while an internal staging path exceeds the host limit. Short build,
workspace, and profile roots remain useful when that policy is disabled; changing
the Registry is not required for short-path operation. See
[Windows path diagnostics](troubleshooting.md#windows-path-exceeds-the-supported-limit).

## C++ Formatting

Use the `clang-format` version recorded in `.clang-format-version` and the rules in `.clang-format`. The project targets C++23; clang-format 22.1.8 has no `c++23` value for `Standard`, so the config keeps `Latest` with the tool version pinned. To verify all tracked C++ files in PowerShell:

```powershell
$expected = (Get-Content .clang-format-version -Raw).Trim()
if ((clang-format --version) -notmatch [regex]::Escape($expected)) { throw "Expected clang-format $expected" }
$files = @(git ls-files -- '*.cpp' '*.hpp')
clang-format --dry-run --Werror @files
```

## Embedded Locale Generation

The build generates `generated/cli/i18n_embedded.hpp` from `locales/en.json` and `locales/pt-BR.json` using `scripts/generate_i18n_embedded.py`. The generated header is a build artifact, not a checked-in source file. The generator emits bounded raw C++ string fragments to remain compatible with MSVC limits while preserving source bytes, including line endings. Keep the generated file under the build tree; do not hand-edit it.

## CMake Presets

`CMakePresets.json` defines presets using the Ninja generator:

On Windows, run preset commands from a Visual Studio 2022 developer shell for
MSVC, or an MSYS2 UCRT64 shell with its GCC, CMake, and Ninja on `PATH`. Keep one
compiler per build directory; choose a separate directory for another toolchain.

### Debug (with tests enabled)

```powershell
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

The `debug` preset configures a `Debug` build in `build-debug/` with `BUILD_TESTING=ON`.

### Release

```powershell
cmake --preset default
cmake --build --preset default
```

The `default` preset configures a `Release` build in `build/`. The resulting binary is located at `build/kasumi.exe` on Windows or `build/kasumi` on Linux.

---

## Direct Builds (Without Presets)

### GCC (Windows and Linux)

```powershell
cmake -S . -B build-gcc -G Ninja -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build-gcc --parallel
ctest --test-dir build-gcc --output-on-failure
```

When using GCC on Windows with MinGW/MSYS2, CMake links `stdc++exp` and applies static linking flags (`-static`) in Release configurations. On Linux, standard GCC builds link the toolchain runtime libraries without `stdc++exp` or `-static`.

### MSVC / Visual Studio 2022 (Windows)

```powershell
cmake -S . -B build-msvc -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTING=ON
cmake --build build-msvc --config Debug --parallel
ctest --test-dir build-msvc -C Debug --output-on-failure
```

This configuration exercises the MSVC toolchain with multi-config build support. MSVC builds use the static C/C++ runtime (/MT in Release, /MTd in Debug).

### Clang (Windows — MSYS2 CLANG64)

From an MSYS2 CLANG64 shell with `mingw-w64-clang-x86_64-clang`, `mingw-w64-clang-x86_64-ninja`, `mingw-w64-clang-x86_64-cmake`, and `mingw-w64-clang-x86_64-python` installed:

```bash
# Debug build and test
cmake -S . -B build-clang64-debug -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build-clang64-debug
ctest --test-dir build-clang64-debug --output-on-failure --parallel 2

# Release build and test
cmake -S . -B build-clang64-release -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build-clang64-release
ctest --test-dir build-clang64-release --output-on-failure --parallel 2
```

### Clang (Ubuntu / Linux)

On Ubuntu with `clang`, `cmake`, and `ninja-build` installed:

```bash
# Debug build and test
cmake -S . -B build-clang-debug -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DBUILD_TESTING=ON
cmake --build build-clang-debug -j$(nproc)
ctest --test-dir build-clang-debug --output-on-failure

# Release build and test
cmake -S . -B build-clang-release -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DBUILD_TESTING=ON
cmake --build build-clang-release -j$(nproc)
ctest --test-dir build-clang-release --output-on-failure
```

---

## Test Execution and Filters

To run test suites with `ctest`:

```powershell
# Run all tests in the debug build directory
ctest --test-dir build-debug --output-on-failure

# Filter tests by label category
ctest --test-dir build-debug -L unit --output-on-failure
ctest --test-dir build-debug -L integration --output-on-failure
ctest --test-dir build-debug -L e2e.local_sync --output-on-failure
ctest --test-dir build-debug -L release-critical --output-on-failure --no-tests=error

# Filter tests by name pattern
ctest --test-dir build-debug -R ^kasumi_architecture_dag$ --output-on-failure
```

The release-critical selection covers crypto, formats, paths, protected history,
GC, authenticated Sync repair, journal/crash recovery, and Fsck. Run it alongside
the full suite; record skipped and disabled tests separately. `--no-tests=error`
rejects an empty selection.

Specific test labels include:
* `unit.platform`
* `unit.crypto`
* `unit.application.history_storage`
* `unit.application`
* `integration.sync`
* `integration.runtime_application`
* `integration.contracts`
* `release-critical`

The `kasumi_architecture_dag` test validates internal architectural dependency rules enforced by the dependency DAG checker script.

## Operational Performance Trace

Use [performance tracing](troubleshooting.md#slow-synchronization-or-preview)
for PowerShell, CMD, and POSIX command examples and interpretation of scanner,
hash-cache, and remote-observation metrics. `KASUMI_PERF_TRACE=1` writes counters
and accumulated wall-clock microseconds for instrumented operations to `stderr`.
Audit-style inspection commands may fetch and validate content objects rather
than relying only on structural metadata.

## Rclone System Tests

System tests exercise integration with an active rclone installation:

```powershell
cmake -S . -B build-system -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON -DKASUMI_BUILD_SYSTEM_TESTS=ON
cmake --build build-system --parallel
ctest --test-dir build-system -L system.rclone --output-on-failure
```

Place `rclone` on `PATH` or specify the executable path explicitly using `-DKASUMI_RCLONE_EXECUTABLE=<path-to-rclone>`.

## Operational Benchmarks

Benchmark harnesses are repository tools for measuring operational performance characteristics:

```powershell
cmake -S . -B build-bench -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DKASUMI_BUILD_BENCHMARKS=ON
cmake --build build-bench --parallel
```

Benchmark executables and scripts are located in `tests/operational/`.

### GC performance

Build `kasumi_benchmark_gc` with `KASUMI_BUILD_BENCHMARKS=ON`, then run:

```powershell
New-Item -ItemType Directory -Force benchmark-results | Out-Null
python tests/operational/benchmark_gc.py --binary build-bench/tests/kasumi_benchmark_gc.exe --output benchmark-results/gc-local --candidates 0 100 1000 5000 20000 --samples 2
python tests/unit/operational/test_gc_benchmark.py
```

The output directory must be new. Each sample creates a fresh, isolated vault,
random test key and authenticated history with one protected Content object.
Orphan payloads are encrypted small files; fixture creation, the direct GC call
on an already-open transport, post-GC FSCK and fixture cleanup have separate
timings. These are not end-to-end CLI startup/recovery measurements. Tracing is
enabled only for GC by the executable; `KASUMI_PERF_TRACE=1` enables the same
instrumentation for normal commands. Peak RSS is the benchmark process only:
it excludes rclone children, includes fixture memory and is not a GC-only
allocation measurement.

`results.json` retains each sample, raw metrics, binary SHA-256, and median/min/max
for successful samples. A missing metric is `null`, never an invented zero.
Malformed/truncated output, a missing result, process failure, uncertain cleanup
or timeout stops the campaign without retry. The workspace, private test key,
owned-object inventory and available diagnostics remain for investigation.
Successful fixture cleanup removes only known objects; empty directories and
local evidence may remain. Timings have no fixed pass/fail budget.
During rclone GC, `GC_PROGRESS` lines expose the existing progress callback in
the sample's live stderr log. They add no remote observation or ownership check.

For a real rclone backend, obtain explicit permission for a dedicated parent
outside any existing vault, inspect that exact path read-only, and start small:

```powershell
rclone lsf "test-remote:disposable-parent" --max-depth 1
python tests/operational/benchmark_gc.py --binary build-bench/tests/kasumi_benchmark_gc.exe --output benchmark-results/gc-remote-100 --remote-parent "test-remote:disposable-parent" --confirm-disposable-parent --candidates 100 --samples 1
```

Pass the parent as `remote:path` without a trailing slash. The harness creates a
random child below it and never writes to the parent directly. If the parent is
new, `lsf` reports `directory not found`; the preflight still proves the random
child unused from transport and raw-RC missing-directory evidence before the
first write creates the prefix.
`--confirm-disposable-parent` records previously obtained authorization; it does
not make an existing vault disposable. The harness rejects a remote root,
placeholders, traversal and any `Programming` path component. It uses the
existing GC-live preflight to prove a random child unused, checks its empty
listing, verifies a separate owner marker, and puts the vault below that child.
No production profile, credentials database or SQLite state is used. Configure
`RCLONE_CONFIG` separately if needed; do not put credentials in command arguments.

Inspect the 100-object result before scheduling 1,000 or 5,000 objects in another
new output directory. A 20,000-object remote run additionally requires
`--confirm-large-remote` after reviewing provider costs and limits. The default
local candidate list includes 20,000, so always specify remote sizes explicitly.
Each run performs bounded batches of at most eight candidate DELETEs and may be slow or rate limited.
The report keeps Kasumi transport/RC metrics separate from unavailable internal
provider retries (`null`); successful local/rclone-local tests do not certify a
cloud provider. Never use purge/delete commands or automatic barrier recovery
to clean an uncertain run. See [GC](architecture/garbage-collection.md#tracing).

The journal E2E campaign uses the real CLI, official Publisher/Receiver profiles,
physical SQLite databases, and real rclone local/cloud storage. Keep all output
outside the repository; each run preserves its exclusive namespace and artifacts:

```powershell
python tests/operational/benchmark_journal_e2e.py --binary build-clang64-release/kasumi.exe --rclone-config C:/private/rclone.conf --output <external-output-directory> --group-commit
python tests/operational/test_journal_preparation_e2e.py --binary build-clang64-release/kasumi.exe --rclone "C:/Program Files/rclone/rclone.exe" --rclone-config C:/private/rclone.conf --output <external-output-directory>
```

The preparation regression checks two file counts after verifying all ten real
syncs. It measures the Started-to-FilesStaged interval, including both durable
barriers, separately from later completion checkpoints.

For deterministic abrupt-process recovery tests, use a **separate test build**:

```powershell
cmake -S . -B build-journal-fault -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DKASUMI_BUILD_JOURNAL_FAULT_TESTS=ON
cmake --build build-journal-fault --target kasumi
python tests/operational/test_journal_recovery_e2e.py --binary build-journal-fault/kasumi.exe --rclone "C:/Program Files/rclone/rclone.exe" --output <external-output-directory> --expect-grouped
```

This runner creates its own rclone `type=local` configuration and does not read
global credentials. Hooks terminate without destructors at observed transaction
boundaries or inject persistence errors. They are compiled out unless explicitly
enabled; production and performance builds must keep the option **OFF**.

The [current journal contract](architecture/transaction-journal.md) documents
authenticated confirmation, retirement, rollback and format incompatibility.
The process runner preserves journal artifacts and checks repeated recovery;
these process exits do not simulate physical power loss.

### Remote Inspection Benchmark

The `benchmark_remote_inspection.py` harness measures remote history inspection across multiple phases:

```powershell
python tests/operational/benchmark_remote_inspection.py `
  --kasumi build/kasumi.exe `
  --output build/remote-inspection.json `
  --commits 64 `
  --delta 3 `
  --repetitions 1 `
  --remote remote:dedicated-folder `
  --rclone-config C:/path/to/rclone.conf
```

The harness records `cold`, `warm`, `delta`, `re_warm`, and `corrupted_cache` execution phases. Recorded timings provide comparative evaluation data across configurations, rather than serving as absolute performance limits. Omitting `--remote` and `--rclone-config` causes the benchmark to use a temporary local transport directory.
