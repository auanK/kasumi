#include "platform/folder_icon.hpp"
#include "platform/private_storage.hpp"

#include <algorithm>
#include <cstring>
#include <cwctype>
#include <string>
#include <system_error>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <commoncontrols.h>
#include <wincodec.h>
#endif

namespace kasumi::platform {

#ifdef _WIN32
namespace {

struct ComInitGuard {
    HRESULT hr = E_FAIL;

    explicit ComInitGuard(DWORD coinit = COINIT_MULTITHREADED) noexcept
        : hr(CoInitializeEx(nullptr, coinit)) {}

    ~ComInitGuard() noexcept {
        if (hr == S_OK || hr == S_FALSE) {
            CoUninitialize();
        }
    }

    ComInitGuard(const ComInitGuard&) = delete;
    ComInitGuard& operator=(const ComInitGuard&) = delete;
};

struct BitmapHandleGuard {
    HBITMAP handle = nullptr;

    BitmapHandleGuard() noexcept = default;
    ~BitmapHandleGuard() noexcept {
        if (handle != nullptr) {
            DeleteObject(handle);
        }
    }

    BitmapHandleGuard(const BitmapHandleGuard&) = delete;
    BitmapHandleGuard& operator=(const BitmapHandleGuard&) = delete;
};

struct IconHandleGuard {
    HICON handle = nullptr;

    IconHandleGuard() noexcept = default;
    ~IconHandleGuard() noexcept {
        if (handle != nullptr) {
            DestroyIcon(handle);
        }
    }

    IconHandleGuard(const IconHandleGuard&) = delete;
    IconHandleGuard& operator=(const IconHandleGuard&) = delete;
};

template <typename T>
struct ComReleaseGuard {
    T* ptr = nullptr;

    explicit ComReleaseGuard(T* p = nullptr) noexcept : ptr(p) {}
    ~ComReleaseGuard() noexcept {
        if (ptr != nullptr) {
            ptr->Release();
        }
    }

    ComReleaseGuard(const ComReleaseGuard&) = delete;
    ComReleaseGuard& operator=(const ComReleaseGuard&) = delete;
};

std::optional<std::wstring> utf8_to_wide(std::string_view utf8) {
    if (utf8.empty()) {
        return std::wstring{};
    }
    const int needed = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()),
        nullptr, 0);
    if (needed <= 0) {
        return std::nullopt;
    }
    std::wstring wide(static_cast<std::size_t>(needed), L'\0');
    const int converted = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()),
        wide.data(), needed);
    if (converted <= 0) {
        return std::nullopt;
    }
    return wide;
}

bool contains_traversal_segment(std::wstring_view path) noexcept {
    std::size_t start = 0;
    while (start <= path.size()) {
        const auto sep = path.find_first_of(L"/\\", start);
        const auto len = sep == path.npos ? path.size() - start : sep - start;
        const auto seg = path.substr(start, len);
        if (seg == L"..") {
            return true;
        }
        if (sep == path.npos) {
            break;
        }
        start = sep + 1;
    }
    return false;
}

std::wstring wide_lower(std::wstring_view text) {
    std::wstring out(text);
    std::ranges::transform(out, out.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return out;
}

bool starts_with_ci(std::wstring_view text, std::wstring_view prefix) {
    return text.size() >= prefix.size() &&
           wide_lower(text.substr(0, prefix.size())) == wide_lower(prefix);
}

std::filesystem::path normalize_dir_path(const std::filesystem::path& path) {
    auto norm = path.lexically_normal();
    while (!norm.empty() && !norm.has_filename() && norm.has_relative_path()) {
        norm = norm.parent_path();
    }
    return norm;
}

bool is_under_base_dir(const std::filesystem::path& candidate,
                        const std::filesystem::path& base,
                        bool case_insensitive) {
    const auto norm_base = normalize_dir_path(base);
    const auto norm_cand = candidate.lexically_normal();
    if (norm_base.empty() || norm_cand.empty()) {
        return false;
    }
    std::wstring base_str = norm_base.wstring();
    std::wstring cand_str = norm_cand.wstring();
    if (case_insensitive) {
        base_str = wide_lower(base_str);
        cand_str = wide_lower(cand_str);
    }
    if (cand_str.size() <= base_str.size() ||
        cand_str.compare(0, base_str.size(), base_str) != 0) {
        return false;
    }
    return cand_str[base_str.size()] == L'\\' ||
           cand_str[base_str.size()] == L'/';
}

bool has_reparse_segment_from_base(const std::filesystem::path& candidate,
                                   const std::filesystem::path& base) {
    const auto norm_base = normalize_dir_path(base);
    const auto norm_cand = candidate.lexically_normal();
    const auto base_lower = wide_lower(norm_base.wstring());
    if (private_storage::is_reparse_or_symlink(norm_base)) {
        return true;
    }
    for (auto cur = norm_cand; !cur.empty(); cur = cur.parent_path()) {
        if (private_storage::is_reparse_or_symlink(cur)) {
            return true;
        }
        if (wide_lower(cur.wstring()) == base_lower) {
            return false;
        }
        if (cur == cur.root_path()) {
            break;
        }
    }
    return true;
}

std::optional<std::filesystem::path> system_windows_directory() {
    wchar_t buf[MAX_PATH]{};
    const UINT len = GetSystemWindowsDirectoryW(buf, MAX_PATH);
    if (len == 0) {
        return std::nullopt;
    }
    if (len < MAX_PATH) {
        return normalize_dir_path(std::filesystem::path(std::wstring_view(buf, len)));
    }
    std::wstring large(len, L'\0');
    const UINT written = GetSystemWindowsDirectoryW(large.data(), len);
    if (written == 0 || written >= len) {
        return std::nullopt;
    }
    large.resize(written);
    return normalize_dir_path(std::filesystem::path(std::move(large)));
}

bool has_allowed_win32_icon_source(const std::filesystem::path& path) {
    const auto ext = wide_lower(path.extension().wstring());
    return ext == L".dll" || ext == L".exe" || ext == L".ico";
}

std::optional<std::wstring>
resolve_safe_icon_resource_path(const std::filesystem::path& folder_path,
                                std::string_view raw_resource) {
    if (raw_resource.find('\0') != raw_resource.npos) {
        return std::nullopt;
    }
    const auto wide_raw = utf8_to_wide(raw_resource);
    if (!wide_raw || wide_raw->empty() ||
        contains_traversal_segment(*wide_raw)) {
        return std::nullopt;
    }

    const std::wstring& raw = *wide_raw;
    if (raw.starts_with(L"\\\\") || raw.starts_with(L"//") ||
        raw.starts_with(L"\\??\\") || raw.starts_with(L"\\") ||
        raw.starts_with(L"/")) {
        return std::nullopt;
    }
    if (raw.find(L':', raw.size() >= 2 && raw[1] == L':' ? 2U : 0U) !=
        std::wstring::npos) {
        return std::nullopt;
    }
    if (raw.size() >= 2 && raw[1] == L':') {
        const wchar_t drive = raw[0];
        if (!((drive >= L'A' && drive <= L'Z') ||
              (drive >= L'a' && drive <= L'z')) ||
            raw.size() < 3 || (raw[2] != L'\\' && raw[2] != L'/')) {
            return std::nullopt;
        }
    }

    const auto win_dir = system_windows_directory();
    std::filesystem::path system32;
    std::filesystem::path syswow64;
    if (win_dir) {
        system32 = normalize_dir_path(*win_dir / L"System32");
        syswow64 = normalize_dir_path(*win_dir / L"SysWOW64");
    }

    bool from_system_env = false;
    std::wstring resolved_text;
    static constexpr std::wstring_view kSysRootSlash = L"%SystemRoot%\\";
    static constexpr std::wstring_view kSysRootFSlash = L"%SystemRoot%/";
    static constexpr std::wstring_view kWinDirSlash = L"%windir%\\";
    static constexpr std::wstring_view kWinDirFSlash = L"%windir%/";
    std::size_t env_prefix_len = 0;
    if (starts_with_ci(raw, kSysRootSlash) ||
        starts_with_ci(raw, kSysRootFSlash)) {
        env_prefix_len = kSysRootSlash.size();
    } else if (starts_with_ci(raw, kWinDirSlash) ||
               starts_with_ci(raw, kWinDirFSlash)) {
        env_prefix_len = kWinDirSlash.size();
    }
    if (env_prefix_len > 0) {
        if (!win_dir) {
            return std::nullopt;
        }
        from_system_env = true;
        resolved_text = (*win_dir / raw.substr(env_prefix_len)).wstring();
    } else {
        resolved_text = raw;
    }

    if (resolved_text.find(L'%') != std::wstring::npos ||
        contains_traversal_segment(resolved_text)) {
        return std::nullopt;
    }

    const std::filesystem::path parsed(resolved_text);
    const std::filesystem::path norm_folder = normalize_dir_path(folder_path);
    std::filesystem::path candidate;
    std::filesystem::path trusted_base;

    if (from_system_env) {
        candidate = parsed.lexically_normal();
        if (is_under_base_dir(candidate, system32, true)) {
            trusted_base = system32;
        } else if (is_under_base_dir(candidate, syswow64, true)) {
            trusted_base = syswow64;
        } else {
            return std::nullopt;
        }
    } else if (parsed.has_root_name() && parsed.has_root_directory()) {
        candidate = parsed.lexically_normal();
        if (win_dir && is_under_base_dir(candidate, system32, true)) {
            trusted_base = system32;
        } else if (win_dir && is_under_base_dir(candidate, syswow64, true)) {
            trusted_base = syswow64;
        } else if (is_under_base_dir(candidate, norm_folder, true)) {
            trusted_base = norm_folder;
        } else {
            return std::nullopt;
        }
    } else if (!parsed.has_root_name() && !parsed.has_root_directory()) {
        candidate = (norm_folder / parsed).lexically_normal();
        if (!is_under_base_dir(candidate, norm_folder, true)) {
            return std::nullopt;
        }
        trusted_base = norm_folder;
    } else {
        return std::nullopt;
    }

    if (!has_allowed_win32_icon_source(candidate) ||
        has_reparse_segment_from_base(candidate, trusted_base)) {
        return std::nullopt;
    }
    std::error_code ec;
    const auto st = std::filesystem::symlink_status(candidate, ec);
    if (ec || std::filesystem::is_symlink(st) ||
        !std::filesystem::is_regular_file(st)) {
        return std::nullopt;
    }
    return candidate.wstring();
}

HICON extract_explicit_icon(const std::wstring& binary_path, int index) noexcept {
    HICON icon = nullptr;
    UINT icon_id = 0;
    const UINT extracted = PrivateExtractIconsW(binary_path.c_str(),
                                                index,
                                                48,
                                                48,
                                                &icon,
                                                &icon_id,
                                                1,
                                                LR_DEFAULTCOLOR);
    if (extracted > 0 && icon != nullptr) {
        return icon;
    }
    HICON large_icon = nullptr;
    if (ExtractIconExW(binary_path.c_str(), index, &large_icon, nullptr, 1) > 0 &&
        large_icon != nullptr) {
        return large_icon;
    }
    return nullptr;
}

HICON extract_shell_folder_icon(const std::filesystem::path& folder_path) {
    const std::wstring wide_folder = folder_path.wstring();
    SHFILEINFOW sfi{};
    if (SHGetFileInfoW(wide_folder.c_str(),
                       0,
                       &sfi,
                       sizeof(sfi),
                       SHGFI_SYSICONINDEX) != 0) {
        IImageList* raw_list = nullptr;
        if (SUCCEEDED(SHGetImageList(
                SHIL_EXTRALARGE, IID_PPV_ARGS(&raw_list))) &&
            raw_list != nullptr) {
            ComReleaseGuard<IImageList> list_guard{raw_list};
            HICON shell_icon = nullptr;
            if (SUCCEEDED(raw_list->GetIcon(
                    sfi.iIcon, ILD_TRANSPARENT, &shell_icon)) &&
                shell_icon != nullptr) {
                return shell_icon;
            }
        }
    }
    SHFILEINFOW fallback{};
    if (SHGetFileInfoW(wide_folder.c_str(),
                       0,
                       &fallback,
                       sizeof(fallback),
                       SHGFI_ICON | SHGFI_LARGEICON) != 0) {
        return fallback.hIcon;
    }
    return nullptr;
}

std::optional<ThumbnailResult>
encode_wic_source(IWICImagingFactory* raw_factory,
                  IWICBitmapSource* source,
                  bool prefer_jpeg,
                  std::uint64_t max_bytes) {
    IStream* raw_stream = nullptr;
    if (FAILED(CreateStreamOnHGlobal(nullptr, TRUE, &raw_stream)) ||
        raw_stream == nullptr) {
        return std::nullopt;
    }
    ComReleaseGuard<IStream> stream{raw_stream};

    const GUID container =
        prefer_jpeg ? GUID_ContainerFormatJpeg : GUID_ContainerFormatPng;
    IWICBitmapEncoder* raw_encoder = nullptr;
    if (FAILED(raw_factory->CreateEncoder(container, nullptr, &raw_encoder)) ||
        raw_encoder == nullptr) {
        return std::nullopt;
    }
    ComReleaseGuard<IWICBitmapEncoder> encoder{raw_encoder};

    if (FAILED(raw_encoder->Initialize(raw_stream, WICBitmapEncoderNoCache))) {
        return std::nullopt;
    }

    IPropertyBag2* raw_bag = nullptr;
    IWICBitmapFrameEncode* raw_frame = nullptr;
    if (FAILED(raw_encoder->CreateNewFrame(
            &raw_frame, prefer_jpeg ? &raw_bag : nullptr)) ||
        raw_frame == nullptr) {
        if (raw_bag != nullptr) {
            raw_bag->Release();
        }
        return std::nullopt;
    }
    ComReleaseGuard<IWICBitmapFrameEncode> frame{raw_frame};
    ComReleaseGuard<IPropertyBag2> prop_bag{raw_bag};

    if (prefer_jpeg && raw_bag != nullptr) {
        PROPBAG2 option{};
        option.pstrName = const_cast<LPOLESTR>(L"ImageQuality");
        VARIANT quality{};
        quality.vt = VT_R4;
        quality.fltVal = 0.85f;
        static_cast<void>(raw_bag->Write(1, &option, &quality));
    }

    if (FAILED(raw_frame->Initialize(raw_bag))) {
        return std::nullopt;
    }
    UINT width = 0;
    UINT height = 0;
    if (FAILED(source->GetSize(&width, &height)) || width == 0 || height == 0) {
        return std::nullopt;
    }
    if (FAILED(raw_frame->SetSize(width, height))) {
        return std::nullopt;
    }
    WICPixelFormatGUID format = prefer_jpeg ? GUID_WICPixelFormat24bppBGR
                                            : GUID_WICPixelFormat32bppBGRA;
    static_cast<void>(raw_frame->SetPixelFormat(&format));
    if (FAILED(raw_frame->WriteSource(source, nullptr))) {
        return std::nullopt;
    }
    if (FAILED(raw_frame->Commit()) || FAILED(raw_encoder->Commit())) {
        return std::nullopt;
    }

    HGLOBAL hglobal = nullptr;
    if (FAILED(GetHGlobalFromStream(raw_stream, &hglobal)) ||
        hglobal == nullptr) {
        return std::nullopt;
    }
    STATSTG stat{};
    if (FAILED(raw_stream->Stat(&stat, STATFLAG_NONAME)) ||
        stat.cbSize.QuadPart == 0 || stat.cbSize.QuadPart > max_bytes) {
        return std::nullopt;
    }
    const auto byte_count = static_cast<std::size_t>(stat.cbSize.QuadPart);
    const void* locked = GlobalLock(hglobal);
    if (locked == nullptr) {
        return std::nullopt;
    }
    const auto* ptr = static_cast<const std::uint8_t*>(locked);
    std::vector<std::uint8_t> out(ptr, ptr + byte_count);
    GlobalUnlock(hglobal);
    return ThumbnailResult{
        std::move(out),
        prefer_jpeg ? std::string_view{"image/jpeg"}
                    : std::string_view{"image/png"},
    };
}

std::optional<ThumbnailResult>
scale_and_encode_wic_source(IWICImagingFactory* raw_factory,
                            IWICBitmapSource* source,
                            UINT src_w,
                            UINT src_h,
                            UINT max_dim,
                            bool use_jpeg,
                            std::uint64_t max_bytes) {
    const UINT longest = (std::max)(src_w, src_h);
    if (longest > max_dim) {
        const double ratio =
            static_cast<double>(max_dim) / static_cast<double>(longest);
        const UINT dst_w = (std::max)(
            UINT{1},
            static_cast<UINT>(static_cast<double>(src_w) * ratio + 0.5));
        const UINT dst_h = (std::max)(
            UINT{1},
            static_cast<UINT>(static_cast<double>(src_h) * ratio + 0.5));
        IWICBitmapScaler* raw_scaler = nullptr;
        if (FAILED(raw_factory->CreateBitmapScaler(&raw_scaler)) ||
            raw_scaler == nullptr) {
            return std::nullopt;
        }
        ComReleaseGuard<IWICBitmapScaler> scaler{raw_scaler};
        if (FAILED(raw_scaler->Initialize(
                source, dst_w, dst_h, WICBitmapInterpolationModeFant))) {
            return std::nullopt;
        }
        return encode_wic_source(raw_factory, raw_scaler, use_jpeg, max_bytes);
    }
    return encode_wic_source(raw_factory, source, use_jpeg, max_bytes);
}

std::optional<std::vector<std::uint8_t>> encode_hicon_png(HICON icon) {
    if (icon == nullptr) {
        return std::nullopt;
    }
    IWICImagingFactory* raw_factory = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WICImagingFactory,
                                nullptr,
                                CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&raw_factory))) ||
        raw_factory == nullptr) {
        return std::nullopt;
    }
    ComReleaseGuard<IWICImagingFactory> factory{raw_factory};

    IWICBitmap* raw_bitmap = nullptr;
    if (FAILED(raw_factory->CreateBitmapFromHICON(icon, &raw_bitmap)) ||
        raw_bitmap == nullptr) {
        return std::nullopt;
    }
    ComReleaseGuard<IWICBitmap> bitmap{raw_bitmap};

    auto encoded =
        encode_wic_source(raw_factory, raw_bitmap, false, 512ULL * 1024ULL);
    return encoded ? std::optional{std::move(encoded->bytes)} : std::nullopt;
}

} // namespace

std::optional<std::vector<std::uint8_t>>
extract_folder_icon_png(const std::filesystem::path& folder_path,
                        std::optional<std::string_view> resource_path,
                        std::optional<int> resource_index) {
    ComInitGuard com{COINIT_APARTMENTTHREADED};
    if (FAILED(com.hr) && (resource_path ? com.hr != RPC_E_CHANGED_MODE : true)) {
        return std::nullopt;
    }
    IconHandleGuard icon;
    if (resource_path) {
        const auto resolved =
            resolve_safe_icon_resource_path(folder_path, *resource_path);
        if (!resolved) {
            return std::nullopt;
        }
        icon.handle =
            extract_explicit_icon(*resolved, resource_index.value_or(0));
    } else {
        std::error_code ec;
        const auto st = std::filesystem::symlink_status(folder_path, ec);
        if (ec || std::filesystem::is_symlink(st) ||
            private_storage::is_reparse_or_symlink(folder_path) ||
            !std::filesystem::is_directory(st)) {
            return std::nullopt;
        }
        icon.handle = extract_shell_folder_icon(folder_path);
    }
    return encode_hicon_png(icon.handle);
}

std::optional<ThumbnailResult>
scale_image_thumbnail(std::span<const std::uint8_t> encoded_image,
                      std::uint32_t max_dimension,
                      bool prefer_jpeg) {
    if (encoded_image.empty() || max_dimension == 0) {
        return std::nullopt;
    }
    ComInitGuard com;
    if (FAILED(com.hr) && com.hr != RPC_E_CHANGED_MODE) {
        return std::nullopt;
    }
    IWICImagingFactory* raw_factory = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WICImagingFactory,
                                nullptr,
                                CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&raw_factory))) ||
        raw_factory == nullptr) {
        return std::nullopt;
    }
    ComReleaseGuard<IWICImagingFactory> factory{raw_factory};

    HGLOBAL hmem = GlobalAlloc(GMEM_MOVEABLE, encoded_image.size());
    if (hmem == nullptr) {
        return std::nullopt;
    }
    void* dst = GlobalLock(hmem);
    if (dst == nullptr) {
        GlobalFree(hmem);
        return std::nullopt;
    }
    std::memcpy(dst, encoded_image.data(), encoded_image.size());
    GlobalUnlock(hmem);

    IStream* raw_in_stream = nullptr;
    if (FAILED(CreateStreamOnHGlobal(hmem, TRUE, &raw_in_stream)) ||
        raw_in_stream == nullptr) {
        GlobalFree(hmem);
        return std::nullopt;
    }
    ComReleaseGuard<IStream> in_stream{raw_in_stream};

    IWICBitmapDecoder* raw_decoder = nullptr;
    if (FAILED(raw_factory->CreateDecoderFromStream(
            raw_in_stream,
            nullptr,
            WICDecodeMetadataCacheOnDemand,
            &raw_decoder)) ||
        raw_decoder == nullptr) {
        return std::nullopt;
    }
    ComReleaseGuard<IWICBitmapDecoder> decoder{raw_decoder};

    IWICBitmapFrameDecode* raw_frame = nullptr;
    if (FAILED(raw_decoder->GetFrame(0, &raw_frame)) || raw_frame == nullptr) {
        return std::nullopt;
    }
    ComReleaseGuard<IWICBitmapFrameDecode> frame{raw_frame};

    UINT src_w = 0;
    UINT src_h = 0;
    constexpr UINT kMaxDimension = 16384U;
    constexpr std::uint64_t kMaxPixelCount = 64'000'000ULL;
    if (FAILED(raw_frame->GetSize(&src_w, &src_h)) || src_w == 0 ||
        src_h == 0 || src_w > kMaxDimension || src_h > kMaxDimension ||
        static_cast<std::uint64_t>(src_w) * static_cast<std::uint64_t>(src_h) >
            kMaxPixelCount) {
        return std::nullopt;
    }

    const bool use_jpeg = prefer_jpeg || (max_dimension > 256U);
    const std::uint64_t max_thumb_bytes =
        (max_dimension > 256U) ? (4ULL * 1024ULL * 1024ULL)
                               : (512ULL * 1024ULL);
    return scale_and_encode_wic_source(raw_factory,
                                       raw_frame,
                                       src_w,
                                       src_h,
                                       max_dimension,
                                       use_jpeg,
                                       max_thumb_bytes);
}

std::optional<ThumbnailResult>
extract_shell_thumbnail(const std::filesystem::path& file_path,
                        std::uint32_t max_dimension) {
    if (max_dimension == 0) {
        return std::nullopt;
    }
    const auto norm_path = file_path.lexically_normal();
    std::error_code ec;
    const auto st = std::filesystem::symlink_status(norm_path, ec);
    if (ec || std::filesystem::is_symlink(st) ||
        private_storage::is_reparse_or_symlink(norm_path) ||
        private_storage::is_reparse_or_symlink(norm_path.parent_path()) ||
        !std::filesystem::is_regular_file(st)) {
        return std::nullopt;
    }
    const UINT target = (std::clamp)(max_dimension, 48U, 1400U);

    ComInitGuard com{COINIT_APARTMENTTHREADED};
    if (FAILED(com.hr)) {
        return std::nullopt;
    }

    const std::wstring wide_path = norm_path.wstring();
    IShellItemImageFactory* raw_item = nullptr;
    if (FAILED(SHCreateItemFromParsingName(
            wide_path.c_str(), nullptr, IID_PPV_ARGS(&raw_item))) ||
        raw_item == nullptr) {
        return std::nullopt;
    }
    ComReleaseGuard<IShellItemImageFactory> item{raw_item};

    BitmapHandleGuard hbmp;
    const SIZE requested{static_cast<LONG>(target), static_cast<LONG>(target)};
    if (FAILED(raw_item->GetImage(
            requested, SIIGBF_THUMBNAILONLY | SIIGBF_BIGGERSIZEOK, &hbmp.handle)) ||
        hbmp.handle == nullptr) {
        return std::nullopt;
    }

    IWICImagingFactory* raw_factory = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WICImagingFactory,
                                nullptr,
                                CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&raw_factory))) ||
        raw_factory == nullptr) {
        return std::nullopt;
    }
    ComReleaseGuard<IWICImagingFactory> factory{raw_factory};

    IWICBitmap* raw_bitmap = nullptr;
    if (FAILED(raw_factory->CreateBitmapFromHBITMAP(
            hbmp.handle, nullptr, WICBitmapIgnoreAlpha, &raw_bitmap)) ||
        raw_bitmap == nullptr) {
        return std::nullopt;
    }
    ComReleaseGuard<IWICBitmap> bitmap{raw_bitmap};

    UINT src_w = 0;
    UINT src_h = 0;
    constexpr UINT kMaxDimension = 16384U;
    if (FAILED(raw_bitmap->GetSize(&src_w, &src_h)) || src_w == 0 ||
        src_h == 0 || src_w > kMaxDimension || src_h > kMaxDimension) {
        return std::nullopt;
    }

    const std::uint64_t max_bytes =
        (target > 256U) ? (4ULL * 1024ULL * 1024ULL) : (512ULL * 1024ULL);
    return scale_and_encode_wic_source(
        raw_factory, raw_bitmap, src_w, src_h, target, true, max_bytes);
}

#else

std::optional<std::vector<std::uint8_t>>
extract_folder_icon_png(const std::filesystem::path&,
                        std::optional<std::string_view>,
                        std::optional<int>) {
    return std::nullopt;
}

std::optional<ThumbnailResult>
scale_image_thumbnail(std::span<const std::uint8_t>,
                      std::uint32_t,
                      bool) {
    return std::nullopt;
}

std::optional<ThumbnailResult>
extract_shell_thumbnail(const std::filesystem::path&,
                        std::uint32_t) {
    return std::nullopt;
}

#endif

} // namespace kasumi::platform
