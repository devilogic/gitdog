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
   @file crypt_register_prng.c
   Register a PRNG, Tom St Denis
*/
  
static void switch_prng(int x) {
	struct ltc_prng_descriptor *prng = &prng_descriptor[x];   /* 没有对应槽的算法 */
	
	/* 找到自己对应的位置了，并且自己的位置也没有并占用 */
	if (prng_descriptor[prng->ID].name == NULL) {
		XMEMCPY(&prng_descriptor[prng->ID], prng, sizeof(struct ltc_prng_descriptor));
		return;
	}

	/* 继续递归 */
	switch_prng(prng->ID);
}


/**
   Register a PRNG with the descriptor table
   @param prng   The PRNG you wish to register
   @return value >= 0 if successfully added (or already present), -1 if unsuccessful
*/
int register_prng(const struct ltc_prng_descriptor *prng)
{
	int x;

	LTC_ARGCHK(prng != NULL);

	/* is it already registered? */
	LTC_MUTEX_LOCK(&ltc_prng_mutex);
	for (x = 0; x < TAB_SIZE; x++) {
		if (XMEMCMP(&prng_descriptor[x], prng, sizeof(struct ltc_prng_descriptor)) == 0) {
			LTC_MUTEX_UNLOCK(&ltc_prng_mutex);
			return x;
		}
	}

	/* 直接使用ID对应索引号进行注册 */
	if (prng_descriptor[prng->ID].name == NULL) {
		XMEMCPY(&prng_descriptor[prng->ID], prng, sizeof(struct ltc_prng_descriptor));
		LTC_MUTEX_UNLOCK(&ltc_prng_mutex);
		return prng->ID;
	} else {
		switch_prng(prng->ID);
		XMEMCPY(&prng_descriptor[prng->ID], prng, sizeof(struct ltc_prng_descriptor));
		LTC_MUTEX_UNLOCK(&ltc_prng_mutex);
		return prng->ID;	   
	}

	/* find a blank spot */
	for (x = 0; x < TAB_SIZE; x++) {
		if (prng_descriptor[x].name == NULL) {
			XMEMCPY(&prng_descriptor[x], prng, sizeof(struct ltc_prng_descriptor));
			prng_descriptor[x].ID = x;	/* add by devilogic */
			LTC_MUTEX_UNLOCK(&ltc_prng_mutex);
			return x;
		}
	}

	/* no spot */
	LTC_MUTEX_UNLOCK(&ltc_prng_mutex);
	return -1;
}

/* $Source$ */
/* $Revision$ */
/* $Date$ */
