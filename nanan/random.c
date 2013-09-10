#include "random.h"
#include "tools.h"

#include <tomcrypt.h>

int randomInit() {
	int err;

#if defined(LTC_YARROW)
	if ((err = register_prng(&yarrow_desc)) == -1) {
		return err;
	}
#endif


#if defined(LTC_SPRNG)
	if ((err = register_prng(&sprng_desc)) == -1) {
		return err;
	}
#endif

#if defined(LTC_RC4)
	if ((err = register_prng(&rc4_desc)) == -1) {
		return err;
	}

#endif

#if defined(LTC_FORTUNA)
	if ((err = register_prng(&fortuna_desc)) == -1) {

		return err;
	}

#endif

#if defined(LTC_SOBER128)	
	if ((err = register_prng(&sober128_desc)) == -1) {
		return err;
	}

#endif

	return CRYPT_OK;

}

int randomMakePrng(int id, prng_state* state) {
	int err;

	LTC_ARGCHK(state != NULL);

	if ((err = prng_is_valid(id)) != CRYPT_OK)
		return err;

	if ((err = rng_make_prng(64, id, state, NULL)) != CRYPT_OK)
		return err;

	return CRYPT_OK;
}


void randomPrintAlgorithm(int print_id) {
	int x = 0;

	for (x = 0; prng_descriptor[x].name != NULL; x++) {
		if (print_id)
			printf("%d %s\n", prng_descriptor[x].ID, 
					prng_descriptor[x].name);
		else
			printf("%s\n", prng_descriptor[x].name);
	}
}

