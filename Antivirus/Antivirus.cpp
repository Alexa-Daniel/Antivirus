#include "Antivirus.h"
#include <filesystem>
#include <string>
#include <set>
#include <fstream>
#include <windows.h>
#include <wincrypt.h>
#include <sstream>
#include <iomanip>
#include <wintrust.h>
#include <SoftPub.h>
#include "BloomFilter.hpp"
#include "Aho-Corasick.hpp"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")

#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <vector>
#include <functional>
#include <optional>

using namespace std;

TrieNode* trie = nullptr;
const unsigned int BIN_HASH_SIZE = 32;
const std::streamsize HEURISTIC_READ_LIMIT = 1048576;

void loadBloomFilter(BloomFilter& bf)
{
    ifstream file("..\\hash_db\\bloom_filter.bin", ios::binary);
    if (file.is_open())
    {
        bf.load(file);
        file.close();
    }
    else
    {
        //cerr << "[ERROR]: Could not load bloom_filter.bin!\n";
    }
}

vector<uint8_t> createHash(const filesystem::path& file, string& bucketName)
{
    std::vector<uint8_t> binaryHash;

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        //cerr << "[ERROR]: CryptAcquireContext failed\n";
        return binaryHash;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        //cerr << "[ERROR]: CryptCreateHash failed\n";
        CryptReleaseContext(hProv, 0);
        return binaryHash;
    }

    hFile = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        //cerr << "[ERROR]: CreateFileW failed: " << GetLastError() << "\n";
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return binaryHash;
    }

    BOOL bResult = false;
    DWORD cbRead = 0;
    BYTE rgbFile[1024];

    while (bResult = ReadFile(hFile, rgbFile, 1024, &cbRead, NULL))
    {
        if (cbRead == 0)
        {
            break;
        }

        if (!CryptHashData(hHash, rgbFile, cbRead, 0))
        {
            //cerr << "[ERROR]: CryptoHashData failed: " << GetLastError() << '\n';
            CloseHandle(hFile);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return binaryHash;
        }
    }

    DWORD cbHash = 32;
    BYTE rgbHash[32];
    if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        //cerr << "[ERROR] CryptGetHashParam failed: " << GetLastError() << '\n';
        CloseHandle(hFile);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return binaryHash;
    }

    stringstream ss;
    ss << hex << setfill('0');
    ss << setw(2) << (int)rgbHash[0];
    ss << setw(2) << (int)rgbHash[1];
    bucketName = "..\\hash_db\\";
    bucketName.append(ss.str());
    bucketName.append(".bin");

    binaryHash.assign(rgbHash, rgbHash + cbHash);

    CloseHandle(hFile);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return binaryHash;
}

bool checkHash(string bucketName, vector<uint8_t> fileHash)
{
    //cout << bucketName;
    ifstream hashesFile(bucketName, ios::binary | ios::ate);

    if (!hashesFile.is_open())
    {
        //cout << "Couldn't open the file containing the corresponding hashes\n";
        return false;
    }

    uintmax_t hashesFileLg;
    try
    {
        hashesFileLg = filesystem::file_size(bucketName);
    }
    catch (filesystem::filesystem_error e)
    {
        //cout << e.what();
        return false;
    }

    if (hashesFileLg == 0 || hashesFileLg % BIN_HASH_SIZE)
    {
        //cout << "There were no hashes found in the corresponding file, or the file is corrupted\n";
        return false;
    }

    hashesFile.seekg(0, ios::beg);

    vector<uint8_t> hashes(hashesFileLg);

    if (!hashesFile.read(reinterpret_cast<char*>(hashes.data()), hashesFileLg))
    {
        //cout << "Couldn't read from the file with the corresponding hashes\n";
        return false;
    }

    hashesFile.close();

    for (unsigned int i = 0; i <= hashesFileLg - BIN_HASH_SIZE; i += BIN_HASH_SIZE)
    {
        if (!memcmp(fileHash.data(), hashes.data() + i, BIN_HASH_SIZE))
        {
            return true;
        }
    }

    //cout << "Didn't find the file hash in the corresponding hashes\n";
    return false;
}

void passFiles(string path, set<string>& extensions, BloomFilter& bf)
{
    filesystem::path currPath(path);
    try
    {
        for (const filesystem::directory_entry& entry : filesystem::recursive_directory_iterator(currPath))
        {
            if (entry.is_regular_file())
            {
                string ext = entry.path().extension().string();
                transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (extensions.count(ext))
                {
                    if (isFileTrusted(entry.path()))
                    {
                        continue;
                    }
                    string bucketName;
                    vector<uint8_t> fileHash = createHash(entry.path(), bucketName);

                    if (fileHash.empty())
                    {
                        continue;
                    }

                    if (!bf.check(fileHash.data(), fileHash.size()))
                    {
                        int score = getHeuristicScore(entry.path());
                        if (score >= 100)
                        {
                            
                        }
                        continue;
                    }
                    if (checkHash(bucketName, fileHash))
                    {
                        
                    }
                }
            }
        }
    }
    catch (filesystem::filesystem_error& e)
    {
        //cerr << "[ERROR]: " << e.what() << '\n';
    }
    catch (exception& e)
    {
        //cerr << "[ERROR]: Didn't receive a valid path\n";
    }
}

static std::optional<Detection> processFileTaskReturn(const filesystem::path& filePath, const set<string>& extensions, BloomFilter& bf)
{
    try
    {
        if (!filesystem::is_regular_file(filePath)) return std::nullopt;

        string ext = filePath.extension().string();
        transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        if (!extensions.count(ext)) return std::nullopt;

        if (isFileTrusted(filePath)) return std::nullopt;

        string bucketName;
        vector<uint8_t> fileHash = createHash(filePath, bucketName);

        if (fileHash.empty()) return std::nullopt;

        if (!bf.check(fileHash.data(), fileHash.size()))
        {
            int score = getHeuristicScore(filePath);
            if (score >= 100)
            {
                Detection d;
                d.path = filePath;
                d.type = Detection::Type::Heuristic;
                d.score = score;
                return d;
            }
            return std::nullopt;
        }

        if (checkHash(bucketName, fileHash))
        {
            Detection d;
            d.path = filePath;
            d.type = Detection::Type::Signature;
            d.score = 0;
            return d;
        }

        return std::nullopt;
    }
    catch (...) { return std::nullopt; }
}

void passFilesThreaded(const string& path, set<string>& extensions, BloomFilter& bf, unsigned int numThreads, DetectionCallback onDetection, ProgressCallback onProgress)
{
    filesystem::path currPath(path);

    if (numThreads == 0)
    {
        numThreads = thread::hardware_concurrency();
        if (numThreads == 0) numThreads = 4;
    }

    queue<filesystem::path> filesQueue;
    mutex queueMutex;
    condition_variable cv;
    atomic<bool> finished(false);
    atomic<uint64_t> filesProcessed(0);
    atomic<uint64_t> malwareFound(0);

    const uint64_t progressBatch = 50;

    auto worker = [&](unsigned int id)
    {
        while (true)
        {
            filesystem::path fileToProcess;
            {
                unique_lock<mutex> lk(queueMutex);
                cv.wait(lk, [&]() { return !filesQueue.empty() || finished.load(); });
                if (filesQueue.empty())
                {
                    if (finished.load()) break;
                    else continue;
                }
                fileToProcess = move(filesQueue.front());
                filesQueue.pop();
            }

            auto det = processFileTaskReturn(fileToProcess, extensions, bf);

            uint64_t processed = filesProcessed.fetch_add(1, std::memory_order_relaxed) + 1;
            if (onProgress && (processed % progressBatch == 0))
            {
                onProgress(processed);
            }

            if (det)
            {
                malwareFound.fetch_add(1, std::memory_order_relaxed);
                if (onDetection)
                {
                    onDetection(*det);
                }
            }
        }
    };

    vector<thread> workers;
    workers.reserve(numThreads);
    for (unsigned int i = 0; i < numThreads; ++i)
    {
        workers.emplace_back(worker, i);
    }

    try
    {
        filesystem::directory_options ops = filesystem::directory_options::skip_permission_denied;
        for (const filesystem::directory_entry& entry : filesystem::recursive_directory_iterator(currPath, ops))
        {
            try
            {
                if (entry.is_regular_file())
                {
                    {
                        unique_lock<mutex> lk(queueMutex);
                        filesQueue.push(entry.path());
                    }
                    cv.notify_one();
                }
            }
            catch (...) { /* ignore entry-specific errors */ }
        }
    }
    catch (filesystem::filesystem_error&)
    {

    }
    catch (exception&)
    {
        
    }

    finished.store(true);
    cv.notify_all();

    for (auto& t : workers)
    {
        if (t.joinable()) t.join();
    }

    if (onProgress)
    {
        onProgress(filesProcessed.load());
    }
}

void initializeTrie()
{
    if (trie != nullptr)
    {
        return;
    }
    trie = new TrieNode();
    vector<string> checkWords = { "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "QueueUserAPC",
                                 "NtQueueApcThread", "SetWindowsHookEx", "GetAsyncKeyState", "GetForegroundWindow",
                                 "LsaGetLogonSessionData", "CryptUnprotectData", "sqlite3_open", "LSASS", "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                                 "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "Schtasks.exe", "RegSetValueEx", "powershell -enc",
                                 "URLDownloadToFile", "InternetOpen", "HttpSendRequest", "socket", "CryptEncrypt", "CryptGenKey",
                                 ".locked", ".encrypted", "IsDebuggerPresent", "VMWare", "VirtualBox", "UPX" };
    insert(trie, checkWords);
    buildFailLinks(trie);
}

int getHeuristicScore(const filesystem::path& path)
{
    int score = 0;

    ifstream file(path, ios::binary | ios::ate);
    if (!file.is_open())
    {
        return 0;
    }

    streamsize size = file.tellg();
    if (size == 0)
    {
        file.close();
        return 0;
    }
    file.seekg(0, ios::beg);

    streamsize bytesToRead = min(size, HEURISTIC_READ_LIMIT);

    vector<char> buffer(bytesToRead);
    if (!file.read(buffer.data(), bytesToRead))
    {
        file.close();
        return 0;
    }
    file.close();

    string fileContent(buffer.begin(), buffer.end());

    if (trie == nullptr)
    {
        throw runtime_error("Trie was not initialized");
    }
    map<string, int> matches = search(trie, fileContent);

    if (matches.count("CreateRemoteThread")) score += 40;
    if (matches.count("WriteProcessMemory")) score += 30;
    if (matches.count("VirtualAllocEx")) score += 20;
    if (matches.count("QueueUserAPC")) score += 30;

    if (matches.count("SetWindowsHookEx")) score += 40;
    if (matches.count("GetAsyncKeyState")) score += 15;

    if (matches.count("LsaGetLogonSessionData")) score += 50;
    if (matches.count("CryptUnprotectData")) score += 30;
    if (matches.count("sqlite3_open")) score += 20;
    if (matches.count("LSASS")) score += 30;

    if (matches.count("Software\\Microsoft\\Windows\\CurrentVersion\\Run")) score += 25;
    if (matches.count("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")) score += 25;

    if (matches.count("powershell -enc")) score += 50;
    if (matches.count("URLDownloadToFile")) score += 20;
    if (matches.count("InternetOpen")) score += 5;

    if (matches.count("CryptEncrypt")) score += 15;
    if (matches.count("CryptGenKey")) score += 15;
    if (matches.count(".locked")) score += 30;

    if (matches.count("IsDebuggerPresent")) score += 15;
    if (matches.count("VMWare")) score += 10;
    if (matches.count("VirtualBox")) score += 10;

    if (matches.count("CreateRemoteThread") &&
        matches.count("WriteProcessMemory") &&
        matches.count("VirtualAllocEx"))
    {
        score += 50;
    }

    return score;
}

bool isFileTrusted(const filesystem::path& filePath) {
    LONG lStatus;
    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_FILE_INFO FileInfo;
    WINTRUST_DATA WinTrustData;

    memset(&FileInfo, 0, sizeof(FileInfo));
    FileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileInfo.pcwszFilePath = filePath.c_str();
    FileInfo.hFile = NULL;
    FileInfo.pgKnownSubject = NULL;

    memset(&WinTrustData, 0, sizeof(WinTrustData));
    WinTrustData.cbStruct = sizeof(WINTRUST_DATA);
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.pFile = &FileInfo;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    WinTrustData.dwProvFlags = WTD_SAFER_FLAG;

    lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    return (lStatus == ERROR_SUCCESS);
}