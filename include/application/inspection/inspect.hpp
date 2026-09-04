#ifndef KASUMI_APPLICATION_INSPECTION_INSPECT_HPP
#define KASUMI_APPLICATION_INSPECTION_INSPECT_HPP

#include "application/inspection/request.hpp"
#include "application/inspection/result.hpp"

#include <expected>

namespace kasumi::application {

std::expected<InspectionResponse, InspectionError>
inspect(InspectionInput input);

// Downloads and authenticates a file from the logical tree without modifying local profile.
std::expected<InspectionResponse, InspectionError>
read_remote_file(InspectionInput input);

} // namespace kasumi::application

#endif
