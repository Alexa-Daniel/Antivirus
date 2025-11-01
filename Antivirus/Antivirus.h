#pragma once

#include <filesystem>
#include <string>
#include <set>
#include <vector>
#include <cstdint>

std::vector<uint8_t> createHash(const std::filesystem::path& file, std::string& bucketName);
bool checkHash(std::string bucketName, std::vector<uint8_t> fileHash);