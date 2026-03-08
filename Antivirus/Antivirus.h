#pragma once

#include <filesystem>
#include <string>
#include <set>
#include <vector>
#include <cstdint>
#include <functional>

struct Detection {
    enum class Type { Signature, Heuristic };
    std::filesystem::path path;
    Type type;
    int score;
};

using DetectionCallback = std::function<void(const Detection&)>;
using ProgressCallback = std::function<void(uint64_t)>;

std::vector<uint8_t> createHash(const std::filesystem::path& file, std::string& bucketName);
bool checkHash(std::string bucketName, std::vector<uint8_t> fileHash);
void initializeTrie();
int getHeuristicScore(const std::filesystem::path& filePath);
bool isFileTrusted(const std::filesystem::path& filePath);

void passFilesThreaded(const std::string& path, std::set<std::string>& extensions, class BloomFilter& bf, unsigned int numThreads = 0, DetectionCallback onDetection = nullptr, ProgressCallback onProgress = nullptr);