/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */
#include "tomcrypt.h"

/**
   @file crypt_register_hash.c
   Register a HASH, Tom St Denis
*/

static void switch_hash(int x) {
	struct ltc_hash_descriptor *hash = &hash_descriptor[x];   /* 没有对应槽的算法 */
	
	/* 找到自己对应的位置了，并且自己的位置也没有并占用 */
	if (hash_descriptor[hash->ID].name == NULL) {
		XMEMCPY(&hash_descriptor[hash->ID], hash, sizeof(struct ltc_hash_descriptor));
		return;
	}

	/* 继续递归 */
	switch_hash(hash->ID);
}


/**
   Register a hash with the descriptor table
   @param hash   The hash you wish to register
   @return value >= 0 if successfully added (or already present), -1 if unsuccessful
*/
/*
 * 同register_cipher一样，直接使用ID进行索引对应的注册
 */
int register_hash(const struct ltc_hash_descriptor *hash)
{
	int x;

	LTC_ARGCHK(hash != NULL);

	/* is it already registered? */
	LTC_MUTEX_LOCK(&ltc_hash_mutex);
	for (x = 0; x < TAB_SIZE; x++) {
		if (XMEMCMP(&hash_descriptor[x], hash, sizeof(struct ltc_hash_descriptor)) == 0) {
			LTC_MUTEX_UNLOCK(&ltc_hash_mutex);
			return x;
		}
	}

	/* 直接使用ID对应索引号进行注册 */
	if (hash_descriptor[hash->ID].name == NULL) {
		XMEMCPY(&hash_descriptor[hash->ID], hash, sizeof(struct ltc_hash_descriptor));
		LTC_MUTEX_UNLOCK(&ltc_hash_mutex);
		return hash->ID;
	} else {
		switch_hash(hash->ID);
		XMEMCPY(&hash_descriptor[hash->ID], hash, sizeof(struct ltc_hash_descriptor));
		LTC_MUTEX_UNLOCK(&ltc_hash_mutex);
		return hash->ID;	   
	}

#if 0
	/* find a blank spot */
	for (x = 0; x < TAB_SIZE; x++) {
		if (hash_descriptor[x].name == NULL) {
			XMEMCPY(&hash_descriptor[x], hash, sizeof(struct ltc_hash_descriptor));
			LTC_MUTEX_UNLOCK(&ltc_hash_mutex);
			return x;
		}
	}
#endif

	/* no spot */
	LTC_MUTEX_UNLOCK(&ltc_hash_mutex);
	return -1;
}

/* $Source$ */
/* $Revision$ */
/* $Date$ */
