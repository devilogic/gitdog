#include "nanan.h"

int main(int argc, char* argv[]) {
	int err;
	char buffer[64];
	unsigned char value[128];
	unsigned char value2[128];
	unsigned long value_size;
	unsigned char* pt;
	unsigned char* ct;
	unsigned long pt_len, ct_len;

	char* p;
	PHASH_ALGORITHM hash;
	PCRYPT_ALGORITHM crypt;

	err = randomInit();
	err = hashInit();
	err = cryptInit();
	err = signInit();

	strcpy(buffer, "xixixixiixixi love you");
	
#if 0
	hash = hashAlloc(2);
	err = hashRun2(hash, buffer, strlen(buffer));
	hashPrintResult(hash);
	hashFree(hash);

	hash = hashAlloc(2);
	err = hashRun2(hash, buffer, strlen(buffer));
	hashPrintResult(hash);
	hashFree(hash);
#endif
	
	err = nananHash(buffer, strlen(buffer), value, &value_size);
	err = nananHash(buffer, strlen(buffer), value2, &value_size);
	if (memcmp(value, value2, value_size)) {
		printf("failed\n");
	} else {
		for (err = 0; err < value_size; err++) {
			printf("%02x", value[err]);
		}
		
		printf("\n");

		for (err = 0; err < value_size; err++) {
			printf("%02x", value2[err]);
		}
		printf("success\n");
	}

#if 0
	crypt = cryptAlloc(6, 3, 2, 0, "devilogic");
	err = cryptRun2(crypt, 1, buffer, strlen(buffer));
	cryptPrintResult(crypt, 0);

	p = (char*)malloc(crypt->result_size + 0x10);
	memcpy(p, crypt->result, crypt->result_size);
	
	free(crypt->result);
	crypt->result = NULL;

	err = cryptRun2(crypt, 0, p, crypt->result_size);
	cryptPrintResult(crypt, 1);
	cryptFree(crypt);

	strcpy(buffer, "logic.yan@gmail.com");
	err = nananEncrypt(buffer, strlen(buffer), &ct, &ct_len,
					   "12345");

	{
		int i;
		for (i = 0; i < ct_len; i++)
			printf("%02x", ct[i]);
		printf("\n");
	}

	err = nananDecrypt(ct, ct_len, &pt, &pt_len,
					   "12345");

	{
		int i;
		for (i = 0; i < pt_len; i++)
			printf("%c", pt[i]);
		printf("\n");
	}

	free(pt);
	free(ct);

	// 签名与验证
	{
		unsigned char public_key[2048];
		unsigned long public_key_size;
		unsigned char private_key[2048];
		unsigned long private_key_size;
		char data[1024];
		unsigned char sigdata[1024];
		unsigned long siglen;
		
		err = nananMakeKey(public_key, &public_key_size,
						   private_key, &private_key_size);

		strcpy(data, "devilogic");
		
		err = nananSign(data, strlen(data), 
						sigdata, &siglen,
						private_key, private_key_size);

		err = nananVerify(data, strlen(data), sigdata, siglen, public_key,
						  public_key_size);
		if (err == 0)
			printf("sign success\n");
		else
			printf("sign failed\n");
		
	}
#endif

	return 0;
}
