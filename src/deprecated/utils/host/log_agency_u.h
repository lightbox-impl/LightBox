#ifndef LOG_AGENCY_U_H
#define LOG_AGENCY_U_H

int init_log_agency(const char * logfile, unsigned long int _flags);

void close_log_agency();

void log_flush_timeout();

#endif