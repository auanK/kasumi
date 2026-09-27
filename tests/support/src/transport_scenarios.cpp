#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/provider_scenarios.hpp"

namespace kasumi::test::scenarios {

TransportRoundTripObservation
transport_round_trip(transport::Transport& storage,
                     const std::filesystem::path& scratch_root) {
    TransportRoundTripObservation result;
    const auto source_a = scratch_root / "roundtrip-a.bin";
    const auto source_b = scratch_root / "roundtrip-b.bin";
    const auto destination = scratch_root / "roundtrip-get.bin";
    write_text(source_a, "first");
    write_text(source_b, "second");

    const auto put_zeta = transport::put(storage, source_a, "zeta");
    ++result.requests["put"];
    const auto put_alpha = transport::put(storage, source_b, "alpha");
    ++result.requests["put"];
    const auto present = transport::presence(storage, "alpha");
    ++result.requests["presence"];
    const auto listing = transport::list(storage);
    ++result.requests["list"];
    const auto get = transport::get(storage, "alpha", destination);
    ++result.requests["get"];
    const auto remove_alpha = transport::remove(storage, "alpha");
    ++result.requests["remove"];
    const auto remove_alpha_again = transport::remove(storage, "alpha");
    ++result.requests["remove"];
    const auto remove_zeta = transport::remove(storage, "zeta");
    ++result.requests["remove"];

    const std::vector<std::string> expected_listing{"alpha", "zeta"};
    const bool bytes_ok = get && read_text(destination) == "second";
    if (!put_zeta || !put_alpha || !present ||
        *present != transport::Presence::Present || !listing ||
        *listing != expected_listing || !bytes_ok || !remove_alpha ||
        *remove_alpha != transport::Removal::Removed || !remove_alpha_again ||
        *remove_alpha_again != transport::Removal::AlreadyAbsent ||
        !remove_zeta) {
        result.diagnostics.emplace_back(
            "PUT/PRESENCE/GET/LIST/REMOVE behavior did not match the "
            "round-trip invariant");
    }
    result.passed = result.diagnostics.empty();
    return result;
}

} // namespace kasumi::test::scenarios
