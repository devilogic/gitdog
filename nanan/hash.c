#include "hash.h"
#include "tools.h"

int hashInit() {
	int err;

#ifdef LTC_TIGER
	register_hash (&tiger_desc);
#endif
#ifdef LTC_MD2
	register_hash (&md2_desc);
#endif
#ifdef LTC_MD4
	register_hash (&md4_desc);
#endif
#ifdef LTC_MD5
	register_hash (&md5_desc);
#endif
#ifdef LTC_SHA1
	register_hash (&sha1_desc);
#endif
#ifdef LTC_SHA224
	register_hash (&sha224_desc);
#endif
#ifdef LTC_SHA256
	register_hash (&sha256_desc);
#endif
#ifdef LTC_SHA384
	register_hash (&sha384_desc);
#endif
#ifdef LTC_SHA512
	register_hash (&sha512_desc);
#endif
#ifdef LTC_RIPEMD128
	register_hash (&rmd128_desc);
#endif
#ifdef LTC_RIPEMD160
	register_hash (&rmd160_desc);
#endif
#ifdef LTC_WHIRLPOOL
	register_hash (&whirlpool_desc);
#endif
#ifdef LTC_CHC_HASH
	register_hash(&chc_desc);
	if ((err = chc_register(register_cipher(&aes_desc))) != CRYPT_OK) {
		return err;
	}
#endif
	return CRYPT_OK;
}

PHASH_ALGORITHM hashAlloc(int id) {
	PHASH_ALGORITHM p = (PHASH_ALGORITHM)malloc(sizeof(HASH_ALGORITHM));
	p->id = find_hash_id(id);
	p->count = 0;
	p->result = NULL;
	p->hash_size = hash_descriptor[id].hashsize;

	return p;
}
void hashFree(PHASH_ALGORITHM hash) {
	int i;

	for (i = 0; i < hash->count; i++) {
		free(hash->result[i]);
	}
	free(hash->result);

	hash->id = -1;
	hash->count = 0;
	hash->result = NULL;

	free(hash);
}

int hashRun(PHASH_ALGORITHM hash, int from_stdin, char** files, int count) {
	int x, z, e, id;
	unsigned long w;
	unsigned char* hash_buffer;
	hash_state md;

	id = hash->id;
	
	/*
	printf("count = %d\n", count);
	for (x = 0; x < count; x++) {
		printf("file[%d] = %s\n", x, files[x]);
	}
	*/

	/* 分配结果队列 */
	{
		count = count > 0 ? count : 1;
		int y;
		hash->result = (unsigned char**)malloc(count * sizeof(unsigned char**));
		for (y = 0; y < count; y++) {
			hash->result[y] = (unsigned char*)malloc(MAXBLOCKSIZE);
		}
		hash->count = count;
	}

	if (from_stdin) {
		hash_buffer = hash->result[0];
		hash_descriptor[id].init(&md);
		do {
			x = fread(hash_buffer, 1, sizeof(hash_buffer), stdin);
			hash_descriptor[id].process(&md, hash_buffer, x);
		} while (x == sizeof(hash_buffer));
		if ((e = hash_descriptor[id].done(&md, hash_buffer)) != CRYPT_OK) {
			return e;
		}
	} else {
		for (z = 0; z < count; z++) {
			hash_buffer = hash->result[z];
			w = MAXBLOCKSIZE;
			if ((e = hash_file(id, files[z], 
								hash_buffer, &w)) != CRYPT_OK) {
				return e;
			}
		}
	}

	return CRYPT_OK;
}

int hashRun2(PHASH_ALGORITHM hash, unsigned char* buffer, unsigned long size) {
	int err;
	int x, e, id;
	unsigned long w;
	unsigned char* hash_buffer;
	hash_state md;

	LTC_ARGCHK(hash != NULL);
	LTC_ARGCHK(buffer != NULL);

	id = hash->id;

	{	
		int y;
		w = 1;
		hash->result = (unsigned char**)malloc(w * sizeof(unsigned char**));
		for (y = 0; y < w; y++) {
			hash->result[y] = (unsigned char*)malloc(MAXBLOCKSIZE);
		}
		hash->count = w;
	}

	hash_buffer = hash->result[0];
	hash_descriptor[id].init(&md);

	if (size > MAXBLOCKSIZE) {
		w = size / MAXBLOCKSIZE;
		for (x = 0; x < w; x++) {
			memcpy(hash_buffer, buffer + (x * MAXBLOCKSIZE), MAXBLOCKSIZE);
			hash_descriptor[id].process(&md, 
										hash_buffer, 
										MAXBLOCKSIZE);			
			e = size % MAXBLOCKSIZE;
			memcpy(hash_buffer, buffer + (w * MAXBLOCKSIZE), e);
			hash_descriptor[id].process(&md, 
										hash_buffer, 
										e);
		}
	} else {
		memcpy(hash_buffer, buffer, size);
		hash_descriptor[id].process(&md, hash_buffer, size);
	}

	if ((e = hash_descriptor[id].done(&md, hash_buffer)) != CRYPT_OK) {
		return e;
	}

	return CRYPT_OK;
}

void hashPrintAlgorithm(int print_id) {
	int x = 0;

	for (x = 0; hash_descriptor[x].name != NULL; x++) {
		if (print_id)
			printf("%d %s\n", hash_descriptor[x].ID, 
					hash_descriptor[x].name);
		else
			printf("%s\n", hash_descriptor[x].name);
	}
}

void hashPrintResult(PHASH_ALGORITHM hash) {
	int x, z;
	unsigned char* hash_buffer;

	for (z = 0; z < hash->count; z++) {
		hash_buffer = hash->result[z];
		for (x = 0; x < (int)(hash->hash_size); x++) {
			printf("%02x",hash_buffer[x]);
		}
		printf("\n");
	}
}

