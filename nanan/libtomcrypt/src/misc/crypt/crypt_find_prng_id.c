
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
  @file crypt_find_prng_id.c
  Find a PRNG BY ID, devilogic
*/

/**
   Find a registered PRNG by name
   @param ID The id of the PRNG to look for
   @return >= 0 if found, -1 if not present
*/
int find_prng_id(unsigned char ID)
{
   int x;
   LTC_MUTEX_LOCK(&ltc_prng_mutex);
   for (x = 0; x < TAB_SIZE; x++) {
       if (prng_descriptor[x].ID == ID) {
			x = (prng_descriptor[x].name == NULL) ? -1 : x;
			LTC_MUTEX_UNLOCK(&ltc_prng_mutex);
			return x;
       }
   }
   LTC_MUTEX_UNLOCK(&ltc_prng_mutex);
   return -1;
}


/* $Source$ */
/* $Revision$ */
/* $Date$ */
