#include "nanan.h"
#include "argchk.h"

#include <signal.h>

int nananInit() {
	int e;

	if (((e = randomInit()) != CRYPT_OK) || 
		((e = hashInit()) != CRYPT_OK) ||
		((e = cryptInit()) != CRYPT_OK) ||
		((e = signInit()) != CRYPT_OK)) {
		return e;
	}

	return CRYPT_OK;
}


int nananHash(unsigned char* buffer, 
			  unsigned long len,
			  unsigned char* value,
			  unsigned long* value_len) {
	int err;
	PHASH_ALGORITHM hash;

	hash = hashAlloc(2);
	if (!hash) return CRYPT_ERROR;

	err = hashRun2(hash, buffer, len);
	if (err != CRYPT_OK)
		return CRYPT_ERROR;

	memcpy(value, hash->result[0], hash->hash_size);
	*value_len = hash->hash_size;

	hashFree(hash);

	return err;
}

int nananEncrypt(unsigned char* pt,
				 unsigned long pt_len,
				 unsigned char** ct,
				 unsigned long* ct_len,
				 char* password) {
	int err;

	PCRYPT_ALGORITHM crypt;
	
	crypt = cryptAlloc(6, 3, 2, 0, password);
	if (!crypt) {
		return CRYPT_ERROR;
	}

	err = cryptRun2(crypt, 1, pt, pt_len);
	if (err != CRYPT_OK) {
		cryptFree(crypt);
		return err;
	}

	*ct = (unsigned char*)malloc(crypt->result_size + 0x10);
	memcpy(*ct, crypt->result, crypt->result_size);
	*ct_len = crypt->result_size;

	cryptFree(crypt);

	return err;
}

int nananDecrypt(unsigned char* ct, 
				 unsigned long ct_len,
				 unsigned char** pt,
				 unsigned long* pt_len,
				 char* password) {

	int err;
	PCRYPT_ALGORITHM crypt;
	
	crypt = cryptAlloc(6, 3, 2, 0, password);
	if (!crypt) {
		return CRYPT_ERROR;
	}

	err = cryptRun2(crypt, 0, ct, ct_len);
	if (err != CRYPT_OK) {
		cryptFree(crypt);
		return err;
	}

	*pt = (unsigned char*)malloc(crypt->result_size + 0x10);
	memcpy(*pt, crypt->result, crypt->result_size);
	*pt_len = crypt->result_size;

	cryptFree(crypt);

	return err;
}

int nananMakeKey(unsigned char* public_key,
				 unsigned long* public_key_size,
				 unsigned char* private_key,
				 unsigned long* private_key_size) {
	int err;
	unsigned long len;
	PSIGN_ALGORITHM sign;

	sign = signAlloc(0, 0, 2, 6);
	if (!sign) {
		return CRYPT_ERROR;
	}

	err = signMakePK(sign, NULL);
	if (err != CRYPT_OK) {
		signFree(sign);
		return err;
	}

	memcpy(public_key, sign->public_key, sign->public_key_size);
	*public_key_size = sign->public_key_size;

	memcpy(private_key, sign->private_key, sign->private_key_size);
	*private_key_size = sign->private_key_size;
	
	return CRYPT_OK;
 _error:
	if (sign) signFree(sign);
	return err;
}

int nananSign(unsigned char* buffer,
			  unsigned int len,
			  unsigned char* sigdata,
			  unsigned long* siglen,
			  unsigned char* private_key,
			  unsigned int private_key_size) {
	int err;
	PSIGN_ALGORITHM sign;

	sign = signAlloc(0, 0, 2, 6);
	if (!sign) {
		return CRYPT_ERROR;
	}

	sign->private_key = (unsigned char*)malloc(private_key_size);
	memcpy(sign->private_key, private_key, private_key_size);
	sign->private_key_size = private_key_size;

	err = signImportKey(sign, PK_PRIVATE, NULL);
	if (err != CRYPT_OK) {
		goto _error;
	}

	err = signSignVerify(sign, 
						 SIGN_DATA_FROM_BUF, 0, 
						 buffer, len,
						 sigdata, (unsigned long)siglen);
 _error:
	if (sign) signFree(sign);
	return err;
}

int nananVerify(unsigned char* buffer,
				unsigned int len,
				unsigned char* sigdata,
				unsigned long siglen,
				unsigned char* public_key,
				unsigned int public_key_size,
				int* stat) {
	int err;
	PSIGN_ALGORITHM sign;

	sign = signAlloc(0, 0, 2, 6);
	if (!sign) {
		return CRYPT_ERROR;
	}

	sign->public_key = (unsigned char*)malloc(public_key_size);
	memcpy(sign->public_key, public_key, public_key_size);
	sign->public_key_size = public_key_size;

	err = signImportKey(sign, PK_PUBLIC, NULL);
	if (err != CRYPT_OK) {
		goto _error;
	}

	if ((err = signSignVerify(sign, 
							  SIGN_DATA_FROM_BUF, 1, 
							  buffer, len,
							  sigdata, siglen)) != CRYPT_OK) {
		goto _error;
	}

	*stat = sign->verify_result;

 _error:
	if (sign) signFree(sign);
	return err;
}

#if (ARGTYPE == 0)
void nananArgChk(char *v, char *s, int d) {
	fprintf(stderr, "NANAN_CHKARG '%s' failure on line %d of file %s\n",
			v, d, s);
	(void)raise(SIGABRT);
}
#endif
