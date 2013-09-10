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
   @file crypt_register_cipher.c
   Register a cipher, Tom St Denis
*/

static void switch_cipher(int x) {
	struct ltc_cipher_descriptor *cipher = &cipher_descriptor[x];   /* 没有对应槽的算法 */
	
	/* 找到自己对应的位置了，并且自己的位置也没有并占用 */
	if (cipher_descriptor[cipher->ID].name == NULL) {
		XMEMCPY(&cipher_descriptor[cipher->ID], cipher, sizeof(struct ltc_cipher_descriptor));
		return;
	}

	/* 继续递归 */
	switch_cipher(cipher->ID);
}

/**
   Register a cipher with the descriptor table
   @param cipher   The cipher you wish to register
   @return value >= 0 if successfully added (or already present), -1 if unsuccessful
*/
/*
 * 原来的算法注册有严重的BUG，如果注册的算法的顺序不是按照自身ID的顺序
 * 则最终只能靠find_cipher来获取索引，这里修改为直接索引对应算法ID
 * 但是在使用时还是要使用find_cipher_id进行
 */
int register_cipher(const struct ltc_cipher_descriptor *cipher)
{
	int x;

	LTC_ARGCHK(cipher != NULL);

	/* is it already registered? */
	LTC_MUTEX_LOCK(&ltc_cipher_mutex);
	for (x = 0; x < TAB_SIZE; x++) {
		if (cipher_descriptor[x].name != NULL && cipher_descriptor[x].ID == cipher->ID) {
			LTC_MUTEX_UNLOCK(&ltc_cipher_mutex);
			return x;
		}
	}

	/* 直接使用ID对应索引号进行注册 */
	if (cipher_descriptor[cipher->ID].name == NULL) {
		XMEMCPY(&cipher_descriptor[cipher->ID], cipher, sizeof(struct ltc_cipher_descriptor));
		LTC_MUTEX_UNLOCK(&ltc_cipher_mutex);
		return cipher->ID;
	} else { /* 此时这个槽里存在算法 */
		switch_cipher(cipher->ID);   /* 递归交换完毕后设置自身 */
		XMEMCPY(&cipher_descriptor[cipher->ID], cipher, sizeof(struct ltc_cipher_descriptor));
		LTC_MUTEX_UNLOCK(&ltc_cipher_mutex);
		return cipher->ID;
	}

	/* find a blank spot */
	for (x = 0; x < TAB_SIZE; x++) {
		if (cipher_descriptor[x].name == NULL) {
			XMEMCPY(&cipher_descriptor[x], cipher, sizeof(struct ltc_cipher_descriptor));
			LTC_MUTEX_UNLOCK(&ltc_cipher_mutex);
			return x;
		}
	}

	/* no spot */
	LTC_MUTEX_UNLOCK(&ltc_cipher_mutex);
	return -1;
}

/* $Source$ */
/* $Revision$ */
/* $Date$ */
