#ifndef LOG_H
#define LOG_H

#include "../prads.h"

void log_asset_arp (asset *main);
void log_asset_os (asset *main, os_asset *os, connection *cxt);
void log_asset_service (asset *main, serv_asset *service, connection *cxt);
void log_rotate(time_t);
void log_connection(connection *cxt, int cxstatus);

#endif