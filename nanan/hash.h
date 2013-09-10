#if !defined(__HASH_H__)
#define __HASH_H__

#include <tomcrypt.h>

typedef struct _HASH_ALGORITHM {
	int id;									/* 算法标识 */
	int count;								/* 结果的个数 */
	int hash_size;							/* hash值的长度 */
	unsigned char** result;					/* 结果*/
} HASH_ALGORITHM, *PHASH_ALGORITHM;

int hashInit();
PHASH_ALGORITHM hashAlloc(int id);
void hashFree(PHASH_ALGORITHM hash);
int hashRun(PHASH_ALGORITHM hash, int from_stdin, char** files, int count);
int hashRun2(PHASH_ALGORITHM hash, unsigned char* buffer, unsigned long size);
void hashPrintAlgorithm(int print_id);
void hashPrintResult(PHASH_ALGORITHM hash);

#endif

