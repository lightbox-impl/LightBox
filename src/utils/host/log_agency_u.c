#include "log_agency_u.h"

#include "../prads/prads.h"
#include "../prads/config.h"
#include "../prads/sys_func.h"

#include "../../sg-box/sgbox_config.h"

#include "../prads_u.h"

#include <stdio.h>
#include <string.h>

extern sgx_enclave_id_t global_eid;

FILE *file;
char path[100];
unsigned long int flags;

char buffer[LOG_BUFFER_CAPACITY];

int init_log_agency(const char * logfile, unsigned long int _flags) {
    FILE *fp;
    const char *mode = MODE_READ;
    int retry = 0;
    /* Make sure filename isn't NULL. */
    if (!file)
        return -1;

    memcpy(path, logfile, strlen(logfile));
    flags = _flags;

    /* Check to see if *filename exists. */
reopen:
    if ((fp = fopen(path, mode)) == NULL) {
        int e = errno;
        switch (e) {
        case EISDIR:
        case EFAULT:
        case EACCES:
            /* retry in current working directory */
            if (retry) {
                if (flags & CONFIG_VERBOSE)
                    elog("%s denied opening asset log '%s'", strerror(e), path);
                return e;
            }
            memcpy(path, PRADS_ASSETLOG, strlen(PRADS_ASSETLOG));
            retry++;
            goto reopen;
        case ENOENT:
            mode = MODE_WRITE;
            goto reopen;
        default:
            if (flags & CONFIG_VERBOSE)
                elog("Cannot open file %s: %s!", path, strerror(errno));
            return e;
        }

    }
    else {
        file = fp;

        if (*mode == 'w') {
            /* File did not exist, create new.. */
            fprintf(fp, "asset,vlan,port,proto,service,[service-info],distance,discovered\n");
        }
        /* File does exist, read it into data structure. */
        fclose(fp);
        //       read_report_file();

        /* Open file and assign it to the global FILE pointer.  */
        if ((file = fopen(path, "a")) == NULL) {
            int e = errno;
            if (flags & CONFIG_VERBOSE)
                printf("Cannot open log file %s for append!\n", path);
            return e;
        }
    }

    return 0;
}

void close_log_agency() {
    if (file)
        fclose(file);
}

void log_flush_timeout() {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_log_flush_timeout(global_eid, buffer, LOG_BUFFER_CAPACITY);
    if (ret != SGX_SUCCESS) {
        printf("[*] Failed to flush log upon timeout!\n");
    }

    if (file)
        fwrite(buffer, sizeof(char), LOG_BUFFER_CAPACITY, file);
}

void ocall_log_flush_full(void *_buffer, int useless) {
    if (file)
        fwrite(_buffer, sizeof(char), LOG_BUFFER_CAPACITY, file);
}
