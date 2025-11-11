#include <iostream>
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

using namespace std;

TrieNode* trie = nullptr;
const unsigned int BIN_HASH_SIZE = 32;

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
					string bucketName;
					vector<uint8_t> fileHash = createHash(entry.path(), bucketName);

					if (!bf.check(fileHash.data(), fileHash.size()))
					{
						//cout << "File: " << entry.path() << ": Not malware - from Bloom Filter\n";
						continue;
					}
					if (!fileHash.empty())
					{
						//cout << "File: " << entry.path() << ": ";
						bool malw = checkHash(bucketName, fileHash);
						if (malw)
						{
							//cout << "Malware found: " << "\n";
						}
					}
					//ifstream bucket(bucketName, ios::binary | ios::ate);

					//cout << entry.path().string() << '\n';
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

void initializeTrie()
{
	if (trie != nullptr)
	{
		return;
	}
	trie = new TrieNode();
	vector<string> checkWords = { "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "QueueUserAPC",
								 "NtQueueApcThread", "SetWindowsHookEx", "GetAsyncKeyState", "GetForegroundWindow",
								 "LsaGetLogonSessionData", "CryptUnprotectData", "sqlite3_open", "LSASS", "Software\Microsoft\Windows\CurrentVersion\Run",
								 "Software\Microsoft\Windows\CurrentVersion\RunOnce", "Schtasks.exe", "RegSetValueEx", "powershell -enc",
								 "URLDownloadToFile", "InternetOpen", "HttpSendRequest", "socket", "CryptEncrypt", "CryptGenKey",
								 ".locked", ".encrypted", "IsDebuggerPresent", "VMWare", "VirtualBox", "UPX" };
	insert(trie, checkWords);
	buildFailLinks(trie);
}

int getHeuristicScore(const std::filesystem::path& path)
{
	int score = 0;

	std::ifstream file(path, std::ios::binary | std::ios::ate);
	if (!file.is_open()) 
	{
		return 0;
	}

	std::streamsize size = file.tellg();
	if (size == 0) 
	{
		file.close();
		return 0;
	}
	file.seekg(0, std::ios::beg);

	std::vector<char> buffer(size);
	if (!file.read(buffer.data(), size)) 
	{
		file.close();
		return 0;
	}
	file.close();

	std::string fileContent(buffer.begin(), buffer.end());

	if (trie == nullptr) 
	{
		throw std::runtime_error("Trie was not initialized");
	}
	std::map<std::string, int> matches = search(trie, fileContent);

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