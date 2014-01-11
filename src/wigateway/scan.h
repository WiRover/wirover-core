/*
 *  S C A N . H
 */

#ifndef SCAN_H 
#define SCAN_H

struct interface;
struct ping_stats;
struct ping_client_info;
struct bw_stats;
struct bw_client_info;

void    populateExcludeDevices();
int     checkConnectivity();
int     checkExcludeList(char *name);

int     createScanThread();
int     destroyScanThread();
int     getScanValid(char *name);
int     interfaceScan();
int     interfaceReScan(struct interface *head);
int     scanInterfacesInit();
void    setScanValid(char *name, int value);
void    *scanThreadFunc(void *arg);
void    *scanThreadFuncNew(void *arg);

void    pingHandler(struct ping_client_info* clientInfo, struct link* ife, struct ping_stats* stats);
void    bandwidthHandler(struct bw_client_info* clientInfo, struct link* ife, struct bw_stats* stats);

#endif
