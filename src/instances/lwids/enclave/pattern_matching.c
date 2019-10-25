#include "pattern_matching.h"

#include <enclave/include/utils_t.h>

#include <string.h>

void pcre_init(pcre_t* ppcre_engine, char* regex)
{
    char regex_buffer[10];
    char* sp_loc = regex;
    char* new_loc = 0;
    ppcre_engine->ppcre = calloc(sizeof(pcre*), ppcre_engine->pattern_count);
    for (int i = 0; i < ppcre_engine->pattern_count; i++)
    {
        new_loc = strstr(sp_loc, "|");
        if (new_loc - sp_loc < sizeof(regex_buffer))
        {
            memcpy(regex_buffer, sp_loc, new_loc - sp_loc);
            sp_loc = new_loc + 1;
            eprintf("regex: %d  %s\n", i, regex_buffer);
            ppcre_engine->ppcre[i] = pcre_compile(regex_buffer, // pattern
                0,     // default options
                &ppcre_engine->serror, &ppcre_engine->erroffset,  // errors
                NULL); // default character table

            if (!ppcre_engine->ppcre[i]) {
                eprintf("PCRE compilation failed at offset %d: %s\n", ppcre_engine->erroffset, ppcre_engine->serror);
                abort();
            }
        }
        else
        {
            eprintf("regex_loc: %s  %s\n", sp_loc, new_loc);
        }

    }

}

int pcre_process(pcre_t* ppcre_engine, char* str, int len)
{
    int rc_sum = 0;
    for (int i = 0; i < ppcre_engine->pattern_count; i++)
    {
        int rc = pcre_exec(ppcre_engine->ppcre[i], 0, // pcre engine
            str, len, // query string
            0, // starting offset
            0, // options
            ppcre_engine->output_buffer, PCRE_OVECTOR_SIZE); // output vector of matching positions

        if (rc < 0) {
            switch (rc) {
            case PCRE_ERROR_NOMATCH:
                ppcre_engine->output_len = 4;
                ppcre_engine->output_buffer[0] = PCRE_ERROR_NOMATCH;
                break;
            default:
                break;
            }
        }
        else {
            // no room for all matches, so we return the first 1000
            if (rc == 0)
                rc = PCRE_OVECTOR_SIZE / 3;
            ppcre_engine->output_len = rc * 2 * sizeof(int);
        }

        rc_sum += rc;
    }



    return rc_sum;
}
