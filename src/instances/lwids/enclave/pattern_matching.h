#ifndef PATTERN_MATCHING_H
#define PATTERN_MATCHING_H

#include <pcre.h>

typedef struct
{
    // pcre state
    pcre           **ppcre;
    const char     *serror;
    int             erroffset;

    int pattern_count;


#define PCRE_OVECTOR_SIZE 1000*3 // allow at most 1000 matches
    // output matching positions in the form {s_1,e_1,s_2,e_2,...,}
    // the last n/3 of the array are reserved by libpcre and not used
    int output_buffer[PCRE_OVECTOR_SIZE];

    int output_len;
}pcre_t;

#define TEST_REGEX "ImA|PGn|t3x|zTp|2an|MZ0|zV5|OtA|f9v|08l|" \
                   "Uj9|1wd|aXm|BNU|n8J|dAw|mzn|CpJ|Zx5|dTz|" \
                   "izv|RuG|I08|43Z|utO|dfX|FMj|1WM|YtB|fpY|" \
                   "tNI|15m|DwB|yV8|cvs|jxw|WS1|j6f|9Uh|NMv|" \
                   "LVQ|dI8|xI3|QXJ|Edp|SuW|NvU|KHz|n57|bGW"

void pcre_init(pcre_t* ppcre_engine, char* regex);

int pcre_process(pcre_t* ppcre_engine, char* str, int len);



#endif
