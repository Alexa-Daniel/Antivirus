#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include "BloomFilter.hpp"

using namespace std;

const unsigned int hash_lg = 64;
const unsigned int binary_hash_lg = 32;
const filesystem::path hashDb = "..\\hash_db";
//const string hash_file_path = "eicar_hash.txt";

int hexToInt(char c)
{
	if (c >= '0' && c <= '9')
	{
		return c - '0';
	}
	else if (c >= 'a' && c <= 'z')
	{
		return c - 'a' + 10;
	}
	throw("[ERROR]: Received character is not hexadecimal!");
}

vector<uint8_t> toBinary(string line)
{
	vector<uint8_t> bytes;
	bytes.reserve(binary_hash_lg);
	for (int i = 0; i < hash_lg; i += 2)
	{
		int first = hexToInt(line[i]), second = hexToInt(line[i + 1]);
		uint8_t byte = (first * 16) + second;
		bytes.push_back(byte);
	}
	return bytes;
}

void addToBucket(filesystem::path& bucketPath, vector<uint8_t>& binaryHash)
{
	ofstream file(bucketPath, ios::app | ios::binary);
	if (!file.is_open())
	{
		throw("[ERROR]: Couldn't create or open the bucket file!");
	}
	file.write(reinterpret_cast<const char*>(binaryHash.data()), binary_hash_lg);
	file.close();
}

int main()
{
	BloomFilter bf(1000000, 0.001);
	string hash_file_path;
	cout << "Insert path of the file with hashes to be added to the database (including extension): ";
	getline(cin, hash_file_path);
	cout << hash_file_path;

	try
	{
		if (filesystem::create_directory(hashDb))
		{
			cout << "Succesfully created the database folder\n";
		}
		else
		{
			cout << "Database folder already exists\n";
		}
	}
	catch (filesystem::filesystem_error& e)
	{
		cerr << "[ERROR]: " << e.what() << "\n";
		return -1;
	}

	ifstream file(hash_file_path);
	if (!file.is_open())
	{
		cerr << "[ERROR]: Could not open the file containing all the hashes\n";
		return -2;
	}

	string line;
	int count = 0;
	while (getline(file, line))
	{
		count++;
		if (count % 100000 == 0)
		{
			cout << "Read 100K hashes\n";
		}

		if (line.empty() || line[0] == '#' || line.length() != hash_lg)
		{
			continue;
		}

		try
		{
			vector<uint8_t> binaryHash = toBinary(line);
			bf.add(binaryHash.data(), binaryHash.size());

			string bucketName = line.substr(0, 4);
			filesystem::path bucketPath = hashDb / (bucketName + ".bin");

			addToBucket(bucketPath, binaryHash);
		}
		catch (exception e)
		{
			cerr << "[ERROR]: " << e.what();
		}
	}
	file.close();

	ofstream bloom_file("..\\hash_db\\bloom_filter.bin", ios::binary);
	if (!bloom_file.is_open())
	{
		cerr << "[ERROR]: Could not create bloom.bin file!\n";
	}
	else
	{
		bf.save(bloom_file);
		bloom_file.close();
	}
}