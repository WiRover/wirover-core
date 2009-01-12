/*
 * H A N D L E  T R A N S F E R . H
 */

#ifndef HANDLETRANSFER_H 
#define HANDLETRANSFER_H

// The location of the transfer file to sue for bandwidth testing
#define TRANS_FILE_NAME "/tmp/wirover_bw_test_file"

// The number of bytes to transfer for the static bandwidth measurements
#define TRANS_FILE_SIZE 512000 // Measured in bytes
#define TRANS_TIME_UPPER_BOUND 30

// If the bw calculated from using user traffic across a single link 
// // is greater or equal to the static BW calculated in the beginning
// // times this constant, then use use that estimate as the BW estimate
#define BW_VARIANCE .1

int createHandleTransferThread();
int destroyHandleTransferThread();

FILE    *createTransFile();
int     closeTransFile();

float   recvFile(int trans_sockfd);
float   sendFile(int trans_sockfd);

float   calculateBandwidth(int filesize, float time);

#endif
