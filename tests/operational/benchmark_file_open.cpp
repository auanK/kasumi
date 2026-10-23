#include "application/observation/file_metadata.hpp"
#include "crypto/content.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <blake3.h>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
// clang-format off
#include <windows.h>
// clang-format on
#endif

namespace {

using Clock = std::chrono::steady_clock;

std::uint64_t sink = 0;

bool collect_files(const std::filesystem::path& root,
                   std::vector<std::filesystem::path>& files,
                   std::size_t& skipped_links,
                   std::string& error) {
    files.clear();
    skipped_links = 0;
    std::error_code iterator_error;
    std::filesystem::directory_iterator iterator(
        root, std::filesystem::directory_options::none, iterator_error);
    if (iterator_error) {
        error = "input root is not an accessible directory";
        return false;
    }
    const std::filesystem::directory_iterator end;
    for (; iterator != end; iterator.increment(iterator_error)) {
        if (iterator_error) {
            error = "input enumeration failed";
            return false;
        }
        std::error_code status_error;
        const auto status = iterator->symlink_status(status_error);
        if (status_error) {
            error = "could not inspect input entry";
            return false;
        }
        if (std::filesystem::is_symlink(status)) {
            ++skipped_links;
            continue;
        }
        if (std::filesystem::is_regular_file(status)) {
            files.push_back(iterator->path());
        }
    }
    if (iterator_error) {
        error = "input enumeration failed";
        return false;
    }
    std::ranges::sort(files);
    return true;
}

std::uint64_t elapsed_us(Clock::time_point started) {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() -
                                                              started)
            .count());
}

bool read_ifstream(const std::filesystem::path& path,
                   std::vector<char>& buffer) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return false;
    }
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0) {
            sink ^= static_cast<std::uint64_t>(count);
        }
    }
    return !input.bad() && !(input.fail() && !input.eof());
}

bool hash_ifstream(const std::filesystem::path& path,
                   std::vector<char>& buffer) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return false;
    }
    blake3_hasher state;
    blake3_hasher_init(&state);
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0) {
            blake3_hasher_update(
                &state, buffer.data(), static_cast<std::size_t>(count));
        }
    }
    if (input.bad() || (input.fail() && !input.eof())) {
        return false;
    }
    std::uint8_t digest[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&state, digest, sizeof(digest));
    sink ^= digest[0];
    return true;
}

#if defined(_WIN32)
HANDLE open_attributes(const std::filesystem::path& path) {
    return ::CreateFileW(path.c_str(),
                         FILE_READ_ATTRIBUTES,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr,
                         OPEN_EXISTING,
                         FILE_FLAG_BACKUP_SEMANTICS |
                             FILE_FLAG_OPEN_REPARSE_POINT,
                         nullptr);
}

bool native_open_attributes(const std::filesystem::path& path) {
    const auto handle = open_attributes(path);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    sink ^= reinterpret_cast<std::uintptr_t>(handle);
    ::CloseHandle(handle);
    return true;
}

bool native_metadata(const std::filesystem::path& path) {
    const auto handle = open_attributes(path);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    FILE_BASIC_INFO basic{};
    FILE_STANDARD_INFO standard{};
    FILE_ID_INFO id{};
    const auto read_metadata =
        ::GetFileInformationByHandleEx(
            handle, FileBasicInfo, &basic, sizeof(basic)) != 0 &&
        ::GetFileInformationByHandleEx(
            handle, FileStandardInfo, &standard, sizeof(standard)) != 0 &&
        ::GetFileInformationByHandleEx(handle, FileIdInfo, &id, sizeof(id)) !=
            0;
    if (!read_metadata) {
        ::CloseHandle(handle);
        return false;
    }
    sink ^= static_cast<std::uint64_t>(standard.EndOfFile.QuadPart);
    sink ^= id.VolumeSerialNumber;
    ::CloseHandle(handle);
    return true;
}

bool native_attributes_ex(const std::filesystem::path& path) {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!::GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) {
        return false;
    }
    sink ^= static_cast<std::uint64_t>(data.nFileSizeLow);
    return true;
}

bool native_read(const std::filesystem::path& path,
                 std::vector<char>& buffer,
                 bool hash,
                 DWORD flags = FILE_FLAG_SEQUENTIAL_SCAN) {
    const auto handle = ::CreateFileW(path.c_str(),
                                      GENERIC_READ,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                                      nullptr,
                                      OPEN_EXISTING,
                                      flags | FILE_FLAG_OPEN_REPARSE_POINT,
                                      nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    blake3_hasher state;
    blake3_hasher_init(&state);
    bool ok = true;
    while (true) {
        DWORD count = 0;
        if (::ReadFile(handle,
                       buffer.data(),
                       static_cast<DWORD>(buffer.size()),
                       &count,
                       nullptr) == 0) {
            const auto read_error = ::GetLastError();
            if (read_error != ERROR_HANDLE_EOF && read_error != ERROR_SUCCESS) {
                ok = false;
            }
            break;
        }
        if (count == 0) {
            break;
        }
        if (hash) {
            blake3_hasher_update(&state, buffer.data(), count);
        } else {
            sink ^= count;
        }
    }
    ::CloseHandle(handle);
    if (!ok) {
        return false;
    }
    if (hash) {
        std::uint8_t digest[BLAKE3_OUT_LEN];
        blake3_hasher_finalize(&state, digest, sizeof(digest));
        sink ^= digest[0];
    }
    return true;
}
#endif

struct Mode {
    std::string name;
    std::function<bool()> run;
    bool failed = false;
};

std::vector<Mode> make_modes(const std::filesystem::path& root,
                             const std::vector<std::filesystem::path>& files,
                             std::vector<char>& buffer) {
    std::vector<Mode> modes;
    modes.push_back({"ifstream_open", [&] {
                         bool ok = true;
                         for (const auto& path : files) {
                             std::ifstream input(path, std::ios::binary);
                             if (!input) {
                                 ok = false;
                                 continue;
                             }
                             sink ^= static_cast<std::uint64_t>(input.good());
                         }
                         return ok;
                     }});
    modes.push_back({"ifstream_read", [&] {
                         bool ok = true;
                         for (const auto& path : files) {
                             ok = read_ifstream(path, buffer) && ok;
                         }
                         return ok;
                     }});
    modes.push_back({"ifstream_read_hash", [&] {
                         bool ok = true;
                         for (const auto& path : files) {
                             ok = hash_ifstream(path, buffer) && ok;
                         }
                         return ok;
                     }});
    modes.push_back({"app_hash_file", [&] {
                         bool ok = true;
                         for (const auto& path : files) {
                             const auto result =
                                 kasumi::crypto::content::hash_file(path);
                             ok = result.has_value() && ok;
                             sink ^=
                                 static_cast<std::uint64_t>(result.has_value());
                         }
                         return ok;
                     }});
    modes.push_back({"app_file_metadata", [&] {
                         bool ok = true;
                         for (const auto& path : files) {
                             const auto result =
                                 kasumi::application::observation::cache::
                                     read_file_metadata(path, {});
                             ok = result.has_value() && ok;
                             sink ^=
                                 static_cast<std::uint64_t>(result.has_value());
                         }
                         return ok;
                     }});
    modes.push_back({"fs_symlink_status", [&] {
                         bool ok = true;
                         for (const auto& path : files) {
                             std::error_code error;
                             const auto status =
                                 std::filesystem::symlink_status(path, error);
                             if (error ||
                                 !std::filesystem::is_regular_file(status)) {
                                 ok = false;
                                 continue;
                             }
                             sink ^= 1;
                         }
                         return ok;
                     }});
    modes.push_back({"fs_file_size", [&] {
                         bool ok = true;
                         for (const auto& path : files) {
                             std::error_code error;
                             const auto size =
                                 std::filesystem::file_size(path, error);
                             if (error) {
                                 ok = false;
                                 continue;
                             }
                             sink ^= static_cast<std::uint64_t>(size);
                         }
                         return ok;
                     }});
    modes.push_back({"path_to_utf8", [&] {
                         for (const auto& path : files) {
                             sink ^=
                                 kasumi::platform::path::to_utf8(path).size();
                         }
                         return true;
                     }});
    modes.push_back({"vector_alloc_1m", [&] {
                         for (const auto& path : files) {
                             (void)path;
                             std::vector<char> local(1024U * 1024U);
                             sink ^= static_cast<unsigned char>(local.front());
                         }
                         return true;
                     }});
    modes.push_back(
        {"perf_trace_count_1m", [&] {
             for (std::size_t index = 0; index < 1'000'000; ++index) {
                 kasumi::platform::perf_trace::count("benchmark counter", 1);
             }
             return true;
         }});
    modes.push_back(
        {"perf_trace_begin_finish_1m", [&] {
             for (std::size_t index = 0; index < 1'000'000; ++index) {
                 const auto token = kasumi::platform::perf_trace::begin();
                 kasumi::platform::perf_trace::finish("benchmark timer", token);
             }
             return true;
         }});
    modes.push_back(
        {"directory_enumerate", [&] {
             std::error_code iterator_error;
             std::filesystem::directory_iterator iterator(
                 root,
                 std::filesystem::directory_options::none,
                 iterator_error);
             if (iterator_error) {
                 return false;
             }
             const std::filesystem::directory_iterator end;
             std::size_t regular_files = 0;
             bool ok = true;
             for (; iterator != end; iterator.increment(iterator_error)) {
                 if (iterator_error) {
                     return false;
                 }
                 std::error_code status_error;
                 const auto status = iterator->symlink_status(status_error);
                 if (status_error) {
                     ok = false;
                     continue;
                 }
                 if (std::filesystem::is_regular_file(status)) {
                     ++regular_files;
                 }
             }
             return ok && !iterator_error && regular_files == files.size();
         }});
#if defined(_WIN32)
    modes.push_back({"native_open_attributes", [&] {
                         bool ok = true;
                         for (const auto& path : files) {
                             ok = native_open_attributes(path) && ok;
                         }
                         return ok;
                     }});
    modes.push_back({"native_metadata", [&] {
                         bool ok = true;
                         for (const auto& path : files) {
                             ok = native_metadata(path) && ok;
                         }
                         return ok;
                     }});
    modes.push_back({"native_attributes_ex", [&] {
                         bool ok = true;
                         for (const auto& path : files) {
                             ok = native_attributes_ex(path) && ok;
                         }
                         return ok;
                     }});
    modes.push_back({"native_read", [&] {
                         bool ok = true;
                         for (const auto& path : files) {
                             ok = native_read(path, buffer, false) && ok;
                         }
                         return ok;
                     }});
    modes.push_back({"native_read_hash", [&] {
                         bool ok = true;
                         for (const auto& path : files) {
                             ok = native_read(path, buffer, true) && ok;
                         }
                         return ok;
                     }});
    modes.push_back({"native_read_nohint", [&] {
                         bool ok = true;
                         for (const auto& path : files) {
                             ok = native_read(path, buffer, false, 0) && ok;
                         }
                         return ok;
                     }});
    modes.push_back({"native_read_hash_nohint", [&] {
                         bool ok = true;
                         for (const auto& path : files) {
                             ok = native_read(path, buffer, true, 0) && ok;
                         }
                         return ok;
                     }});
#endif
    return modes;
}

void print_result(const Mode& mode,
                  std::size_t files,
                  std::size_t bytes,
                  std::vector<std::uint64_t> samples) {
    if (mode.failed || samples.empty()) {
        std::cout << "MODE_US|" << mode.name << "|" << files << "|" << bytes
                  << "|INVALID|0|0\n";
        return;
    }
    std::ranges::sort(samples);
    const auto median = samples[samples.size() / 2];
    std::cout << "MODE_US|" << mode.name << "|" << files << "|" << bytes << "|"
              << median << "|" << samples.front() << "|" << samples.back()
              << '\n';
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) {
        std::cerr << "usage: kasumi_benchmark_file_open ROOT [REPS]\n";
        return 2;
    }
    const std::filesystem::path root = argv[1];
    std::size_t repetitions = 5;
    if (argc == 3) {
        const std::string_view text(argv[2]);
        const auto result = std::from_chars(
            text.data(), text.data() + text.size(), repetitions);
        if (result.ec != std::errc{} ||
            result.ptr != text.data() + text.size() || repetitions == 0) {
            std::cerr << "REPS must be a positive integer\n";
            return 2;
        }
    }

    std::vector<std::filesystem::path> files;
    std::size_t skipped_links = 0;
    std::string error;
    if (!collect_files(root, files, skipped_links, error)) {
        std::cerr << error << ": " << kasumi::platform::path::to_utf8(root)
                  << '\n';
        return 1;
    }
    if (skipped_links != 0) {
        std::cout << "SKIPPED|symlink|" << skipped_links << '\n';
    }
    if (files.empty()) {
        std::cerr << "no regular files in "
                  << kasumi::platform::path::to_utf8(root) << '\n';
        return 1;
    }

    std::uint64_t bytes = 0;
    for (const auto& path : files) {
        std::error_code size_error;
        const auto size = std::filesystem::file_size(path, size_error);
        if (size_error ||
            size > std::numeric_limits<std::uint64_t>::max() - bytes) {
            std::cerr << "could not read size for "
                      << kasumi::platform::path::to_utf8(path) << '\n';
            return 1;
        }
        bytes += size;
    }
    std::vector<char> buffer(1024U * 1024U);
    auto modes = make_modes(root, files, buffer);

    for (auto& mode : modes) {
        if (!mode.run()) {
            mode.failed = true;
        }
    }

    std::vector<std::vector<std::uint64_t>> samples(modes.size());
    for (std::size_t repetition = 0; repetition < repetitions; ++repetition) {
        for (std::size_t offset = 0; offset < modes.size(); ++offset) {
            const auto index = (repetition + offset) % modes.size();
            if (modes[index].failed) {
                continue;
            }
            const auto started = Clock::now();
            if (!modes[index].run()) {
                modes[index].failed = true;
                continue;
            }
            samples[index].push_back(elapsed_us(started));
        }
    }

    std::cout << "TRACE|enabled|"
              << (kasumi::platform::perf_trace::enabled() ? 1 : 0) << '\n';
    bool failed = false;
    for (std::size_t index = 0; index < modes.size(); ++index) {
        failed = modes[index].failed || failed;
        print_result(modes[index], files.size(), bytes, samples[index]);
    }
    std::cout << "SINK|" << sink << '\n';
    return failed ? 1 : 0;
}
