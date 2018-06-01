#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include "networking.h"
#include "crypto.h"
#include "../frontend/diagon_alley.h"


/* 
 * struct ConHandle {
 * 	uint64_t id;
 * 	int fd_in;
 * 	int fd_out;
 * 	char key[keyLength];
 * 	sendMsg sendMsg;
 * 	sendMsg recvMsg;
 * 	time_t lastMsg;
 * };
 */

size_t checkRead (void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t ret;

	if ((ret = fread(ptr, size, nmemb, stream)) < nmemb) {
		if (ferror(stream)) {
			perror("fread");
		}
		exitFunc(EXIT_FAILURE);
	}
	return ret;
}

size_t checkWrite (void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t ret;

	if ((ret = fwrite(ptr, size, nmemb, stream)) < nmemb) {
		perror("fwrite");
		exitFunc(EXIT_FAILURE);
	}
	fflush(stream);
	return ret;
}


ConHandle *createCon (FILE *fd_in, FILE *fd_out) {
	ConHandle *con;
	if ((con = calloc(1, sizeof(ConHandle))) == NULL) {
		perror("calloc");
		return NULL;
	}


	srand(time(NULL));
	con->id =  rand();
	con->seq = 0;
	con->fd_in = fd_in;
	con->fd_out = fd_out;
	con->sendMsg = sendDefault;
	con->recvMsg = recvDefault;
	time(&(con->lastMsg));

	return con;
}

int sendHello(ConHandle *con) {
	size_t ptext_len;
	unsigned char *msg;

	if (con->sendMsg(con, "Hello") != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	msg = con->recvMsg(con, &ptext_len);
	if (!msg) {
		return EXIT_FAILURE;
	}
	
	if (strncmp("World", (char *) msg, 5)) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int initSession (ConHandle *con) {
	int err;
	unsigned long buf_len, len, key_len;
	rsa_key *key;
	unsigned char buf[2048];
	
	/* Init encryption */
	initEncryption();

	/* Get remote key */
	key_len = 0;
	len = checkRead(&key_len, 1, sizeof(key_len), con->fd_in);

	len = checkRead(buf, 1, key_len, con->fd_in);
	
	if ((key = calloc(1, sizeof(rsa_key))) == NULL) {
		perror("calloc");
		return EXIT_FAILURE;
	}

	if ((err = rsa_import(buf, len, key)) != CRYPT_OK) {
		return EXIT_FAILURE;
	}

	con->pub = key;


	/* Send to remote party */
	if ((key = calloc(1, sizeof(rsa_key))) == NULL) {
		perror("calloc");
		return EXIT_FAILURE;
	}

	if ((err = genRSAKey(key, KEY_LENGTH)) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	con->priv = key;
	buf_len = sizeof(buf);
	if ((err = rsa_export(buf, &buf_len, PK_PUBLIC, key)) != CRYPT_OK) {
		return EXIT_FAILURE;
	}
	
	len = checkWrite(&buf_len, 1, sizeof(buf_len), con->fd_out);
		
	len = checkWrite(buf, 1, buf_len , con->fd_out);

	return sendHello(con);
}


/*
struct Message {
	uint64_t msg_len;
	uint64_t id;
	uint64_t seq;
	uint64_t payload_len;
	char payload[];
};
*/
int sendDefault (ConHandle *con, const char *text) {
	unsigned char *ctext;
	size_t ctext_len;
	ssize_t msg_len;
	Msg *msg;
	
	if ((ctext = encrypt(con->pub, (unsigned char *) text, strlen(text), &ctext_len)) == NULL) {
		return EXIT_FAILURE;
	}
	
	msg_len = sizeof(Msg) + ctext_len;
	if ((msg = calloc(1, msg_len)) == NULL) {
		perror("calloc");
		return EXIT_FAILURE;
	}
	msg->msg_len = msg_len;
	msg->id = con->id;
	msg->seq = con->seq++;
	msg->payload_len = ctext_len;
	memcpy(msg->payload, ctext, ctext_len);

	checkWrite(msg, 1, msg_len, con->fd_out);

	free(ctext);
	free(msg);
	return EXIT_SUCCESS;
}

unsigned char *recvDefault (ConHandle *con, size_t *ptext_len) {
	ssize_t msg_len;
	Msg *msg;
	unsigned char *ptext;
	
	msg_len = 0;

	checkRead(&msg_len, sizeof(msg_len), 1, con->fd_in);
	
	if ((msg = calloc(1, msg_len)) == NULL) {
		perror("calloc");
		return NULL;
	}

	msg->msg_len = msg_len;

	checkRead(((char *)msg)+8, 1, msg_len-8, con->fd_in);

	if (msg->id != con->id || msg->seq != con->seq) {
		return NULL;
	}
	if ((ptext = decrypt(con->priv, msg->payload, msg->payload_len, ptext_len)) == NULL) {
		return NULL;
	}

	time(&(con->lastMsg));

	free(msg);

	return ptext;
}
