#include "pattern_loader.h"

#include <cstring>
#include <fstream>
#include <vector>

int PatternLoader::load_pattern_file(const char* file,
                                     unsigned char* &pattern_pool,
                                     int *&pattern_length) {
    std::ifstream inFile(file);
    if (!inFile.good()) {
        printf("Cannot open file %s\n", file);
        exit(1);
    }
    else {
        printf("Loading pattern file %s...\n", file);

        std::vector<std::string> ptnSet;
        std::string line;
        int num_pattern = 0;
        int expected_buffer_size = 0;
        while (std::getline(inFile, line, '\n')) {
          if (!line.empty()) {
            ptnSet.push_back(ptrn_str_to_bytes(line));
            ++num_pattern;
            expected_buffer_size += line.size();
          }
        }

        pattern_pool = new unsigned char[expected_buffer_size];
        pattern_length = new int[num_pattern];
        int buffered_size = 0;
        for (int i = 0; i < num_pattern; ++i) {
          pattern_length[i] = ptnSet[i].size();
          memcpy(pattern_pool + buffered_size, ptnSet[i].data(), pattern_length[i]);
          buffered_size += pattern_length[i];
        }

        printf("%d patterns loaded!\n", num_pattern);
        return num_pattern;
    }
}

char PatternLoader::cap_hex_to_byte(const std::string & hex) {
    // first half
    char byte = (hex[0] >= '0' && hex[0] <= '9') ? (hex[0] - '0') : (hex[0] - 'A' + 10); // small letters assumed
    byte *= 16;
    // second half
    byte += (hex[1] >= '0' && hex[1] <= '9') ? (hex[1] - '0') : (hex[1] - 'A' + 10);
    return byte;
}

std::string PatternLoader::ptrn_str_to_bytes(const std::string & str) {
    std::string bytes;

    size_t strlen = str.length();
    for (size_t i = 0; i < strlen; ) {
        // handle binary data in hex form
        if (str[i] == '|') {
            // find next '|' and extract the hex string
            size_t nextDelim = str.find('|', i + 1);
            const std::string& hexes = str.substr(i + 1, nextDelim - i - 1);

            // transform each char
            size_t idx = 0;
            while (idx < hexes.length()) {
                if (hexes[idx] == ' ') {
                    ++idx;
                    continue;
                }
                bytes.push_back(cap_hex_to_byte(hexes.substr(idx, 2)));
                idx += 2;
            }

            // update index
            i = nextDelim + 1;
        }
        // normal character
        else {
            bytes.push_back(str[i]);
            ++i;
        }
    }
    return bytes;
}
