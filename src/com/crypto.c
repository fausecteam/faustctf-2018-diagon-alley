#include <stdint.h>
#include <tfm.h>
//#include <tommath.h>
//#include "libtomcrypt/src/headers/tomcrypt_pkcs.h"
#include "crypto.h"

#define OUT_SIZE 2048
#define L_PARAM ((unsigned char*)"Dissendium")
#define L_PARAM_LEN 10

void initEncryption(void) {
	/* register a math library (in this case TomsFastMath) */
	ltc_mp = tfm_desc;
	//fprintf(stderr, "ltc_mp: %p\n", (void*) &ltc_mp);
	//ltc_mp = ltm_desc;
	//init_TFM();

	/* register prng/hash */
	if (register_prng(&sprng_desc) == -1) {
		exit(EXIT_FAILURE);
	}

	if (register_hash(&sha1_desc) == -1) {
		exit(EXIT_FAILURE);
	}
}

int genRSAKey (rsa_key *key, int key_size) {
	int err, prng_idx;

	prng_idx = find_prng("sprng");

	/* make an RSA-1024 key */
	if ((err = rsa_make_key(NULL, /* PRNG state */
		prng_idx, /* PRNG idx */
		key_size/8, /* 1024-bit key */
		65537, /* we like e=65537 */
		key) /* where to store the key */
		) != CRYPT_OK) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}


unsigned char *encrypt (rsa_key *key, const unsigned char *ptext, const size_t ptext_length, size_t *ctext_length) {
	int err, hash_idx, prng_idx;
	unsigned char *out;

	/* allocate output buffer */
	if ((out = calloc(1, OUT_SIZE)) == NULL) {
		perror("malloc");
		return NULL;
	}

	hash_idx = find_hash("sha1");
	prng_idx = find_prng("sprng");

	/* fill in pt[] with a key we want to send ... */
	*ctext_length = OUT_SIZE;

	if ((err = rsa_encrypt_key_ex(ptext, /* data we wish to encrypt */
							   ptext_length, /* data is 16 bytes long */
							   out, /* where to store ciphertext */
							   ctext_length, /* length of ciphertext */
							   //L_PARAM, /* our lparam for this program */
							   NULL,
							   //L_PARAM_LEN, /* lparam is 7 bytes long */
							   0,
							   NULL, /* PRNG state */
							   prng_idx, /* prng idx */
							   hash_idx, /* hash idx */
							   LTC_PKCS_1_OAEP, /* padding */
							   key) /* our RSA key */
		) != CRYPT_OK) {
		return NULL;
	}
	return out;
}

unsigned char *decrypt (rsa_key *key, const unsigned char *ctext, const size_t ctext_length, size_t *ptext_length) {
	int err, hash_idx, res;
	unsigned char *out;

	/* allocate output buffer */
	if ((out = calloc(1, OUT_SIZE)) == NULL) {
		perror("malloc");
		return NULL;
	}



	hash_idx = find_hash("sha1");


	/* now let’s decrypt the encrypted key */
	*ptext_length = OUT_SIZE;
	if ((err = rsa_decrypt_key_ex(ctext, /* encrypted data */
							   ctext_length, /* length of ciphertext */
							   out, /* where to put plaintext */
							   ptext_length, /* plaintext length */
							   //L_PARAM, /* lparam for this program */
							   NULL,
							   //L_PARAM_LEN, /* lparam is 7 bytes long */
							   0,
							   hash_idx, /* hash idx */
							   LTC_PKCS_1_OAEP, /* padding */
							   &res, /* validity of data */
							   key) /* our RSA key */
		) != CRYPT_OK) {
		return NULL;
	}

	if (res != 1) {
		return NULL;
	}

	return out;
}
