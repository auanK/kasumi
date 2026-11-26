#pragma once

#include "application/daemon/web_http.hpp"
#include "platform/private_storage.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>

namespace kasumi::application::daemon_detail {

inline std::string_view file_media_type(std::string_view path) {
    const auto slash = path.find_last_of('/');
    const auto dot = path.find_last_of('.');
    if (dot == path.npos || (slash != path.npos && dot < slash))
        return "application/octet-stream";
    std::string ext(path.substr(dot));
    std::ranges::transform(ext, ext.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    using Pair = std::pair<std::string_view, std::string_view>;
    constexpr Pair types[]{
        {".png", "image/png"},
        {".jpg", "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".webp", "image/webp"},
        {".gif", "image/gif"},
        {".bmp", "image/bmp"},
        {".avif", "image/avif"},
        {".ico", "image/x-icon"},
        {".svg", "image/svg+xml"},
        {".mp4", "video/mp4"},
        {".webm", "video/webm"},
        {".ogv", "video/ogg"},
        {".mov", "video/quicktime"},
        {".m4v", "video/mp4"},
        {".mp3", "audio/mpeg"},
        {".wav", "audio/wav"},
        {".flac", "audio/flac"},
        {".m4a", "audio/mp4"},
        {".ogg", "audio/ogg"},
        {".opus", "audio/ogg"},
        {".pdf", "application/pdf"},
        {".md", "text/plain; charset=utf-8"},
        {".txt", "text/plain; charset=utf-8"},
    };
    const auto found =
        std::ranges::find(types, std::string_view(ext), &Pair::first);
    return found == std::end(types) ? "application/octet-stream"
                                    : found->second;
}

inline bool
prepare_file_range(const httplib::Request& req,
                   httplib::Response& res,
                   std::uint64_t size,
                   std::optional<platform::private_storage::FileSlice>& slice) {
    if (!req.has_header("Range"))
        return true;
    auto invalid = [&] {
        res.status = 416;
        res.set_header("Content-Range", "bytes */" + std::to_string(size));
        return false;
    };
    if (req.ranges.size() != 1 || !size ||
        size > std::uint64_t{(std::numeric_limits<std::int64_t>::max)()})
        return invalid();
    auto [first, last] = req.ranges.front();
    const auto length = static_cast<std::int64_t>(size);
    if (first == -1) {
        if (last <= 0)
            return invalid();
        first = (std::max)(std::int64_t{0}, length - last);
        last = length - 1;
    }
    if (last == -1 || last >= length)
        last = length - 1;
    if (first < 0 || first > last)
        return invalid();
    // cpp-httplib calculates the response headers and provider offset from
    // these ranges after dispatch.
    const_cast<httplib::Request&>(req).ranges.front() = {first, last};
    slice = platform::private_storage::FileSlice{
        static_cast<std::uint64_t>(first),
        static_cast<std::uint64_t>(last - first + 1)};
    return true;
}

inline bool
write_file_stream(const platform::private_storage::RegularFileInput& input,
                  std::uint64_t offset,
                  std::size_t length,
                  httplib::DataSink& sink) {
    using namespace platform::private_storage;
    if (!seek_regular_file(input, offset))
        return false;
    std::array<std::uint8_t, 65536> buffer;
    while (length) {
        auto part = std::span(buffer).first((std::min)(length, buffer.size()));
        const auto count = read_regular_file(input, part);
        if (!count || !*count ||
            !sink.write(reinterpret_cast<const char*>(buffer.data()), *count))
            return false;
        length -= *count;
    }
    return true;
}

inline void set_file_provider(httplib::Response& res,
                              std::string_view path,
                              std::uint64_t total_size,
                              httplib::ContentProvider provider) {
    const auto mime = file_media_type(path);
    res.set_header("Accept-Ranges", "bytes");
    if (mime == "application/pdf") {
        res.set_header("Content-Disposition", "inline");
        res.set_header(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
    } else {
        res.set_header("Content-Security-Policy",
                       "sandbox; default-src 'none'");
    }
    if (!total_size) {
        res.set_content("", std::string(mime));
        return;
    }
    res.set_content_provider(static_cast<std::size_t>(total_size),
                             std::string(mime),
                             std::move(provider));
}

inline void set_file_stream(
    httplib::Response& res,
    std::string_view path,
    std::uint64_t total_size,
    std::shared_ptr<platform::private_storage::RegularFileInput> input,
    std::uint64_t start = 0) {
    set_file_provider(
        res,
        path,
        total_size,
        [input = std::move(input), start](
            std::size_t offset, std::size_t length, httplib::DataSink& sink) {
            return input && offset >= start &&
                   write_file_stream(*input, offset - start, length, sink);
        });
}

} // namespace kasumi::application::daemon_detail
