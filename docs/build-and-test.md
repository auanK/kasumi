# Build and Test

## Prerequisites

Building Kasumi requires CMake 3.28+, Git, and a C++23 compiler:
* **C++23 Compiler**: A compiler supporting the C++23 features used by the codebase.
* **CMake**: Version 3.28 or later.
* **Git**: Used for dependency retrieval during the build.
* **Ninja**: The provided CMake presets use Ninja.
* **rclone**: Required for rclone-backed remote operation and for system tests that exercise the rclone transport. Not required for building or running local transport tests.

Repository CI exercises:
* Visual Studio 2022 / MSVC on Windows;
* GCC 14 on Windows MSYS2 UCRT64;
* GCC 14 on Linux.

## CMake Presets

`CMakePresets.json` defines presets using the Ninja generator:

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
ctest --test-dir build-debug -L release-critical --output-on-failure

# Filter tests by name pattern
ctest --test-dir build-debug -R ^kasumi_architecture_dag$ --output-on-failure
```

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

Setting `KASUMI_PERF_TRACE=1` enables operational trace instrumentation:

```powershell
$env:KASUMI_PERF_TRACE="1"
./build/kasumi.exe remote commits <profile>
```

Trace output is written to `stderr` and reports call counts and elapsed wall-clock microseconds for instrumented operations. Audit-style inspection commands may fetch and validate content objects rather than relying only on structural metadata.

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
