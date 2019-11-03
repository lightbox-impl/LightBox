#ifndef PATTERNLOADER_H
#define PATTERNLOADER_H

#include <string>

// NOT RAII
class PatternLoader {
public:
	// return pattern_pool_size
    static int load_pattern_file(const char* file, 
                                 unsigned char* &pattern_pool, 
                                 int * &pattern_length);

private:
    static char cap_hex_to_byte(const std::string& hex);

    static std::string ptrn_str_to_bytes(const std::string& str);
};

#endif