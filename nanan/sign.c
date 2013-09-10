#include "sign.h"
#include "random.h"
#include "hash.h"
#include "tools.h"

int signInit() {
	int err;
#if defined(LTM_DESC)
	ltc_mp = ltm_desc;
#endif
	return CRYPT_OK;
}

/* 失败:-1, 成功:实际数据的长度*/
static int input_data_from_file(char* file, 
								unsigned char** buffer, 
								unsigned long* buffer_size) {
	int r, len;
	FILE* fp = fopen(file, "rb");
	if (!fp) return 0;
	/* 计算文件大小 */
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	
	*buffer = (unsigned char*)malloc(len+0x10);
	memset(*buffer, 0, len+0x10);
	r = fread(*buffer, 1, len, fp);
	if (r != len) {
		fclose(fp);
		free(*buffer);
		*buffer = 0;
		*buffer_size = 0;
		return -1;
	}
	*buffer_size = len;
	fclose(fp);
	return len;
}
int signImportKey(PSIGN_ALGORITHM sign, int type, char* key_file_path) {
	int id, e, len;
	unsigned char* public_key;
	unsigned char* private_key;
	unsigned long public_key_size, private_key_size;
	PRSA_ALGORITHM rsa;
	unsigned char* tmpbuf;
	unsigned long tmplen;
	unsigned char* curr;
	unsigned long curr_len;

	id = sign->id;
	rsa = sign->rsa;
	public_key = sign->public_key;
	private_key = sign->private_key;
	public_key_size = sign->public_key_size;
	private_key_size = sign->private_key_size;

	if (key_file_path) {
		if ((len = input_data_from_file(key_file_path, &tmpbuf, &tmplen)) == -1)
			return 1;
	}

	if (type == PK_PRIVATE) {
		if (len) {
			if (sign->private_key)
				free(sign->private_key);
			sign->private_key = tmpbuf;
			private_key = tmpbuf;
			sign->private_key_size = len;
			private_key_size = len;
		}/* end if */

		curr = private_key;
		curr_len = private_key_size;
	} else if ( type == PK_PUBLIC ) {
		if (len) {
			if (sign->public_key)
				free(sign->public_key);
			sign->public_key = tmpbuf;
			public_key = tmpbuf;
			sign->public_key_size = len;
			public_key_size = len;
		}/* end if */
		curr = public_key;
		curr_len = public_key_size;
	}

	if (id == RSA_ID) {				
		e = rsa_import(curr, curr_len, &(rsa->key));
		return e;
	}
	
	return 1;
}

const char* g_public_key_name = "public.key";
const char* g_private_key_name = "private.key";
static int out_key_file(unsigned char* key, unsigned long key_size, int is_public_key, char* key_path) {
	char key_file_path[256];
	FILE* fp;
	int len;

	len = strlen(key_path);
	
	strcpy(key_file_path, key_path);
	if (key_file_path[len - 1] != '/') {
		strcat(key_file_path, "/");
	}

	if (is_public_key)
		strcat(key_file_path, g_public_key_name);
	else
		strcat(key_file_path, g_private_key_name);

	fp = fopen(key_file_path, "wb");
	if (fp == NULL)
		return 1;

	fwrite(key, 1, key_size, fp);
	fflush(fp);
	fclose(fp);

	return 0;
}

const unsigned long g_def_key_buffer_size = 4096;
int signMakePK(PSIGN_ALGORITHM sign, char* key_path) {
	int e;
	int prng_id;
	unsigned long public_key_size, private_key_size;
	unsigned char* public_key;
	unsigned char* private_key;
	PRSA_ALGORITHM rsa;
	prng_state* prng;

	LTC_ARGCHK(sign != NULL);

	rsa = sign->rsa;
	prng_id = sign->prng_id;
	prng = &(sign->prng);

	if (sign->id == RSA_ID) {
		public_key_size = g_def_key_buffer_size;
		private_key_size = g_def_key_buffer_size;
		public_key = (unsigned char*)malloc(public_key_size);
		private_key = (unsigned char*)malloc(private_key_size);

		e = rsa_make_key(prng, prng_id, rsa->key_size,
						 rsa->e,
						 &(rsa->key));
		if (e != CRYPT_OK)
			return e;

		/* 导出key，如果失败则rsa_export中释放分配的内存 */
		e = rsa_export(public_key, &(public_key_size), 
					   PK_PUBLIC, &(rsa->key));
		if (e != CRYPT_OK)
			return e;
		sign->public_key_size = public_key_size;
		sign->public_key = public_key;

		if (key_path)
			if (out_key_file(public_key, public_key_size, 1, key_path))
				return -1;

		/* 导出私钥 */
		e = rsa_export(private_key, &(private_key_size), 
					   PK_PRIVATE, &(rsa->key));
		if (e != CRYPT_OK)
			return e;

		sign->private_key_size = private_key_size;
		sign->private_key = private_key;

		if (key_path)
			if (out_key_file(private_key, private_key_size, 0, key_path))
				return -1;
	} else {
		return -1;
	}

	
	return CRYPT_OK;
}

PSIGN_ALGORITHM signAlloc(int id, int prng_id, int hash_id, int crypt_id) {
	int err;
	PSIGN_ALGORITHM p;

	p = (PSIGN_ALGORITHM)malloc(sizeof(SIGN_ALGORITHM));
	memset(p, 0, sizeof(SIGN_ALGORITHM));

	p->id = id;
	p->prng_id = find_prng_id(prng_id);
	p->hash_id = find_hash_id(hash_id);
	p->crypt_id = find_cipher_id(crypt_id);

	if ((err = randomMakePrng(prng_id, &(p->prng))) != CRYPT_OK) {
		free(p);
		return NULL;
	}

	switch (id) {
	case RSA_ID:
		p->rsa = (PRSA_ALGORITHM)malloc(sizeof(RSA_ALGORITHM));
		p->rsa->e = RSA_DEF_E;
		p->rsa->key_size = RSA_DEF_KEY_SIZE / 8;	
		break;
	case ECC_ID:
		break;
	case DSA_ID:
		break;
	case DH_ID:
		break;
	default:
		free(p);
		p = NULL;
		break;
	}
	return p;
}
void signFree(PSIGN_ALGORITHM sign) {
	if (sign->public_key)
		free(sign->public_key);
	if (sign->private_key)
		free(sign->private_key);
	if (sign->rsa)
		free(sign->rsa);
	if (sign->result)
		free(sign->result);

	//memset(sign, 0, sizeof(SIGN_ALGORITHM));
	free(sign);
}

static char* sign_string[] = {
	"rsa",
	"ecc",
	"dsa",
	"dh"
}; 
void signPrintAlgorithm(int print_id) {
	int i;
	for (i = 0; i < 4; i++) {
		if (print_id)
			printf("%d %s\n", i, sign_string[i]);
		else
			printf("%s\n", sign_string[i]);
	}
}

void signPrintSign(PSIGN_ALGORITHM sign) {
	int i;

	LTC_ARGCHK(sign != NULL);

	if (sign->result == NULL) return;

	for (i = 0; i < sign->result_size; i++) {
		printf("%02x", sign->result[i]);
	}
	printf("\n");
}

void signPrintKey(PSIGN_ALGORITHM sign) {
	int i, id;
	unsigned char* public_key;
	unsigned char* private_key;
	int public_key_size, private_key_size;

	id = sign->id;
	public_key = sign->public_key;
	private_key = sign->private_key;
	public_key_size = sign->public_key_size;
	private_key_size = sign->private_key_size;

	if (id == RSA_ID) {
		/* 打印公钥 */
		for (i = 0; i < public_key_size; i++) {
			printf("%02x", public_key[i]);
		}
		printf("\n");

		/* 打印私钥 */
		for (i = 0; i < private_key_size; i++) {
			printf("%02x", private_key[i]);
		}
		printf("\n");
	}
}

#define MAX_STDIN_BUFFER 1024
static int read_stdin(unsigned char** buf) {
	char input[MAX_STDIN_BUFFER] = {0};
	int c = 0, total = 0;

	do {
		
		if (*buf == NULL) {
			*buf = (unsigned char*)malloc(MAX_STDIN_BUFFER);
		} else {
			unsigned char* tmp = (unsigned char*)malloc(total);
			memcpy(tmp, *buf, total);
			free(*buf);
			*buf = (unsigned char*)malloc(total+MAX_STDIN_BUFFER);
			memcpy(*buf, tmp, total);
			free(tmp);
		}

		memset(input, 0, MAX_STDIN_BUFFER);
		c = fread(input, 1, MAX_STDIN_BUFFER, stdin);
		memcpy((*buf)+total, input, c);
		total += c;

	} while (c >= MAX_STDIN_BUFFER);

	return total;
}

static unsigned long rsa_cale_sign_buffer_size(PRSA_ALGORITHM rsa) {
	rsa_key* key;
	unsigned long modulus_bitlen, modulus_bytelen;

	key = &(rsa->key);

	/* get modulus len in bits */
	modulus_bitlen = mp_count_bits((key->N));

	/* outlen must be at least the size of the modulus */
	modulus_bytelen = mp_unsigned_bin_size((key->N));
	return modulus_bytelen+1;
}

static unsigned long rsa_cale_saltlen(PRSA_ALGORITHM rsa, int hash_id) {
	rsa_key* key;
	unsigned long saltlen;
	unsigned long hLen, modulus_len, modulus_bitlen;
	
	key = &(rsa->key);
	modulus_bitlen = mp_count_bits((key->N));
	
	hLen = hash_descriptor[hash_id].hashsize;
	modulus_len = (modulus_bitlen>>3) + (modulus_bitlen & 7 ? 1 : 0);

	/*
	  if ((saltlen > modulus_len) || (modulus_len < hLen + saltlen + 2)) {
      return CRYPT_PK_INVALID_SIZE;
	  }
	*/
	saltlen = modulus_len - hLen - 2 - 1;

	return saltlen;
}

int signSignVerify(PSIGN_ALGORITHM sign, int source, 
				   int verify, char* data, unsigned long len,
				   unsigned char* sigdata, unsigned long siglen) {
	unsigned char* buf;
	unsigned long bufsize;
	int err, id, hash_id;
	unsigned char hash_buf[MAXBLOCKSIZE];
	unsigned long hash_size;

	LTC_ARGCHK(sign != NULL);
	//LTC_ARGCHK(data != NULL);
	//LTC_ARGCHK(len != 0);
	//LTC_ARGCHK(sigdata != NULL);
	//LTC_ARGCHK(siglen != 0);

	id = sign->id;
	hash_id = sign->hash_id;
	hash_size = 0;

	if (source == SIGN_DATA_FROM_STDIN) {
		bufsize = read_stdin(&buf);
	} else if ((source == SIGN_DATA_FROM_FILE) && (data != NULL)) {
		bufsize = input_data_from_file(data, &buf, &bufsize);
		if (bufsize == -1) return -1;
	} else if (source == SIGN_DATA_FROM_BUF) {
		bufsize = len;
		buf = (unsigned char*)malloc(bufsize + 0x10);
		if (!buf) return -1;
		memset(buf, 0, bufsize + 0x10);
		memcpy(buf, data, len);
	} else {
		return -1;
	}

	if (id == RSA_ID) {

		/* 签名 */
		if (!verify) {
			unsigned long result_size = rsa_cale_sign_buffer_size(sign->rsa);
			unsigned long saltlen = rsa_cale_saltlen(sign->rsa, sign->hash_id);
			sign->result = (unsigned char*)malloc(result_size);
			memset(sign->result, 0, result_size);
			sign->result_size = result_size;

			/* 哈希它 */
			{
				PHASH_ALGORITHM hash;
				hash = hashAlloc(hash_id);
				if (!hash) {
					goto _error;
				}
				err = hashRun2(hash, buf, bufsize);
				if (err != CRYPT_OK) {
					goto _error;
				}
				
				memcpy(hash_buf, hash->result[0], hash->hash_size);
				hash_size = hash->hash_size;
				hashFree(hash);
			}

			err = rsa_sign_hash_ex(hash_buf, 
								   hash_size,
								   sign->result, 
								   &(sign->result_size),
								   LTC_PKCS_1_PSS,
								   &(sign->prng),
								   sign->prng_id,
								   sign->hash_id,
								   saltlen,
								   &(sign->rsa->key));
			if (err != CRYPT_OK) {
				goto _error;
			}

			//memcpy(sigdata, sign->result, sign->result_size);
			//*((unsigned long *)siglen) = sign->result_size;
		} else { /* 验证 */
			int stat;/* 如果签名结果是有效的则返回1否则返回0 */
			unsigned long x, saltlen;

			saltlen = rsa_cale_saltlen(sign->rsa, sign->hash_id);
			hash_id = sign->hash_id;

			//free(buf);/* 这里不需要这个数据 */

			//siglen = input_data_from_file(sigfile, &sig, &siglen);
			//if (siglen == -1)
			//	return -1;

			/* 计算原文件哈希值 */
#if 0
			w = MAXBLOCKSIZE;
			err = hash_file(hash_id, data, hash_buf, &w);
			if (err != CRYPT_OK) {
				goto _error;
			}
#endif

			/* 哈希它 */
			{
				PHASH_ALGORITHM hash;
				hash = hashAlloc(hash_id);
				if (!hash) {
					goto _error;
				}
				err = hashRun2(hash, buf, bufsize);
				if (err != CRYPT_OK) {
					goto _error;
				}
				
				memcpy(hash_buf, hash->result[0], hash->hash_size);
				hash_size = hash->hash_size;
				hashFree(hash);
			}

			err = rsa_verify_hash_ex(sigdata, 
									 siglen,
									 hash_buf, 
									 hash_size,
									 LTC_PKCS_1_PSS,
									 hash_id,
									 saltlen,
									 &stat, &(sign->rsa->key));
			sign->verify_result = stat;
			goto _error;
		}
	}

	return CRYPT_OK;
 _error:
	if (buf) free(buf);
	if (sign->result) free(sign->result);
	return err;
}
