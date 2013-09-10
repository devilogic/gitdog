#if !defined(__RANDOM_H__)
#define __RANDOM_H__

#include <tomcrypt.h>

int randomInit();
void randomPrintAlgorithm(int print_id);
int randomMakePrng(int id, prng_state* state);

#endif

