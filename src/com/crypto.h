#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <tomcrypt.h>
//#include "libtomcrypt/src/headers/tomcrypt.h"

// It doesn't link on debian and I don't have the time to deal with this, so fuck it:
/*
 * Enum ltc_pkcs_1_paddings
 * {
 *   LTC_PKCS_1_V1_5     = 1,        PKCS #1 v1.5 padding (\sa ltc_pkcs_1_v1_5_blocks)
 *   LTC_PKCS_1_OAEP     = 2,        PKCS #1 v2.0 encryption padding
 *   LTC_PKCS_1_PSS      = 3,        PKCS #1 v2.1 signature padding
 *   LTC_PKCS_1_V1_5_NA1 = 4         PKCS #1 v1.5 padding - No ASN.1 (\sa ltc_pkcs_1_v1_5_blocks)
 * };
 */
#define LTC_PKCS_1_OAEP 2


void initEncryption(void);
int genRSAKey (rsa_key *key, const int key_size);
unsigned char *encrypt (rsa_key *key, const unsigned char *ptext, const size_t ptext_length, size_t *ctext_length);
unsigned char *decrypt (rsa_key *key, const unsigned char *ctext, const size_t ctext_length, size_t *ptext_length);

#endif
