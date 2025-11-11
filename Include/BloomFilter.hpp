#pragma once

#include <iostream>
#include <vector>
#include <cmath>
#include <fstream>
#include <cstdint>

class BloomFilter
{
private:

    uint64_t nr_of_bits;
    uint32_t nr_of_hashes;
    std::vector<uint8_t> bytes;

public:

    static uint64_t fnv1a_hash(const unsigned char* data, int lg) {
        uint64_t hash = 0xcbf29ce484222325;
        uint64_t prime = 0x100000001b3;
        for (int i = 0; i < lg; ++i) {
            hash ^= data[i];
            hash *= prime;
        }
        return hash;
    }

    static uint64_t sdbm_hash(const unsigned char* data, int lg) {
        uint64_t hash = 0;
        for (int i = 0; i < lg; ++i) {
            hash = data[i] + (hash << 6) + (hash << 16) - hash;
        }
        return hash;
    }

    BloomFilter() : nr_of_bits(0), nr_of_hashes(0) {}
    BloomFilter(uint64_t nr_of_values, double precision)
    {
        nr_of_bits = static_cast<uint64_t>(std::ceil(-(double(nr_of_values) * std::log(precision)) / (std::log(2.0) * std::log(2.0))));
        nr_of_hashes = static_cast<uint32_t>(std::ceil((double(nr_of_bits) / double(nr_of_values)) * std::log(2.0)));

        bytes.resize(nr_of_bits / 8 + 1, 0);

        std::cout << "Created BloomFilter: \nNR_OF_BYTES: " << nr_of_bits / 8 + 1 << "\nNR_OF_HASHES: " << nr_of_hashes << "\nSIZE: " << bytes.size() / 1024 << "KB\n";
    }

    void add(const unsigned char* hash, unsigned int lg)
    {
        uint64_t h1 = fnv1a_hash(hash, lg);
        uint64_t h2 = sdbm_hash(hash, lg);

        for (int i = 0; i < nr_of_hashes; i++)
        {
            uint64_t pos = (h1 + i * h2) % nr_of_bits;

            bytes[pos / 8] |= 1 << (pos % 8);
        }
    }

    bool check(const unsigned char* hash, unsigned int lg) const
    {
        uint64_t h1 = fnv1a_hash(hash, lg);
        uint64_t h2 = sdbm_hash(hash, lg);

        for (int i = 0; i < nr_of_hashes; i++)
        {
            uint64_t pos = (h1 + i * h2) % nr_of_bits;
            if (!(bytes[pos / 8] & (1 << pos % 8)))
            {
                return false;
            }
        }

        return true;
    }

    void save(std::ofstream& file)
    {
        file.write(reinterpret_cast<char*>(&nr_of_bits), sizeof(nr_of_bits));
        file.write(reinterpret_cast<char*>(&nr_of_hashes), sizeof(nr_of_hashes));
        size_t bytes_size = bytes.size();
        file.write(reinterpret_cast<char*>(&bytes_size), sizeof(bytes_size));
        file.write(reinterpret_cast<char*>(bytes.data()), bytes_size);
    }

    void load(std::ifstream& file)
    {
        file.read(reinterpret_cast<char*>(&nr_of_bits), sizeof(nr_of_bits));
        file.read(reinterpret_cast<char*>(&nr_of_hashes), sizeof(nr_of_hashes));
        size_t bytes_size = 0;
        file.read(reinterpret_cast<char*>(&bytes_size), sizeof(bytes_size));
        bytes.resize(bytes_size);
        file.read(reinterpret_cast<char*>(bytes.data()), bytes_size);
    }
};