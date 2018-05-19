#ifndef LOG_AGENCY_T_H
#define LOG_AGENCY_T_H

void init_logging_agency();

void close_logging_agency();

void log_to_buffer(void *entry, int len);

#endif