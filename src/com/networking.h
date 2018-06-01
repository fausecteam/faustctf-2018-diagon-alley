#ifndef CONNECTION_H
#define CONNECTION_H

#include <stdint.h>
#include <tomcrypt.h>

#define KEY_LENGTH 2048

struct ConHandle;
typedef struct ConHandle ConHandle;

typedef int (*sendMsg) (ConHandle *con, const char *msg);
typedef unsigned char* (*recvMsg) (ConHandle *con, size_t *ptext_len);

struct ConHandle {
	uint64_t id;
	uint64_t seq;
	FILE *fd_in;
	FILE *fd_out;
	rsa_key *pub;
	rsa_key *priv;
	sendMsg sendMsg;
	recvMsg recvMsg;
	time_t lastMsg;
};

struct Message {
	uint64_t msg_len;
	uint64_t id;
	uint64_t seq;
	uint64_t payload_len;
	unsigned char payload[];
};
typedef struct Message Msg;

size_t checkRead (void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t checkWrite (void *ptr, size_t size, size_t nmemb, FILE *stream);

ConHandle *createCon (FILE *fd_in, FILE *fd_out);

int initSession (ConHandle *con);

int sendDefault (ConHandle *con, const char *msg);
unsigned char *recvDefault (ConHandle *con, size_t *ptext_len);
#endif
