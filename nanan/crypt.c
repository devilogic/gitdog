#include "crypt.h"
#include "tools.h"

static char* g_crypt_mode_string[] = {
	"ecb",
	"cbc",
	"cfb",
	"ctr",
	"f8",
	"lrw",
	"ofb",
	"xts",
};

/* 调试专用 */
#if defined(DEBUG)
void print_buffer(unsigned char* buf, unsigned long size) {
	int i;
	for (i = 0; i < size; i++)
		printf("%02x", buf[i]);
	printf("\n");
}

void print_iv(unsigned char* buf, unsigned long size) {
	printf("IV(%d) = ", size);
	print_buffer(buf, size);
}

void print_key(unsigned char* buf, unsigned long size) {
	printf("KEY(%d) = ", size);
	print_buffer(buf, size);
}

#endif


#define DEF_RANDOM_BITS         128
static int get_random_number(int id, 
							 unsigned char* buffer, 
							 unsigned long size) {
	int err;
	prng_state prng;

	if ((err = find_prng_id(id)) == -1)
		return CRYPT_INVALID_PRNG;

	/* 64 - 1024 BITS  */
	if ((err = rng_make_prng(DEF_RANDOM_BITS, id, &prng, NULL)) != CRYPT_OK) {
		return err;
	}

	/* You can use rng_get_bytes on platforms that support it */
	/* x = rng_get_bytes(IV,ivsize,NULL);*/
	err = prng_descriptor[id].read(buffer, size, &prng);
	if (err != size) {
		return CRYPT_ERROR;
	}
  	
	return CRYPT_OK;
}

static int get_iv(PCRYPT_ALGORITHM crypt) {
	int err;

	LTC_ARGCHK(crypt != NULL);

	err = get_random_number(crypt->prng_id, 
							crypt->iv_data, 
							crypt->iv_data_size);
	return err;
}
#define get_tweak     get_iv

static int has_iv(int id) {
	if (id == ECB_MODE) {
		return 0;
	}
	return 1;
}

static int reset_iv(PCRYPT_ALGORITHM crypt, unsigned char* IV) {
	int err;

	switch (crypt->mode) {
#if defined(LTC_CBC_MODE)
	case CBC_MODE:
		err = cbc_setiv(IV, crypt->iv_size, &(crypt->cbc_key));
		break;
#endif

#if defined(LTC_CFB_MODE)
	case CFB_MODE:
		err = cfb_setiv(IV, crypt->iv_size, &(crypt->cfb_key));
		break;
#endif

#if defined(LTC_CTR_MODE)
	case CTR_MODE:
		err = ctr_setiv(IV, crypt->iv_size, &(crypt->ctr_key));
		break;
#endif

#if defined(LTC_F8_MODE)
	case F8_MODE:
		err = f8_setiv(IV, crypt->iv_size, &(crypt->f8_key));
		break;
#endif

#if defined(LTC_LRW_MODE)
	case LRW_MODE:
		err = lrw_setiv(IV, crypt->iv_size, &(crypt->lrw_key));
		break;
#endif

#if defined(LTC_OFB_MODE)
	case OFB_MODE:
		err = ofb_setiv(IV, crypt->iv_size, &(crypt->ofb_key));
		break;
#endif

#if defined(LTC_XTS_MODE)
	case XTS_MODE:
		memcpy(crypt->xts_tweak_key, IV, crypt->iv_size);
		break;
#endif
	default:
		err = CRYPT_OK;
		break;
	}

	return err;
}

static int has_padding(int mode) {
#if defined(LTC_ECB_MODE) || defined(LTC_CBC_MODE) || defined(LTC_LRW_MODE)
	if ((mode == ECB_MODE) ||
		(mode == CBC_MODE) ||
		(mode == LRW_MODE))
		return 1;
#else
	return 0;
#endif

	return 0;
}

/* 成功: 字节数, 失败:0xFFFFFFFF*/
static unsigned long read_padding_size_stream(FILE* fp) {
	int ret;
	unsigned long padding_size;

	padding_size = 0;
	ret = fread(&padding_size, 1, 4, fp);
	if (ret != 4)
		return 0xFFFFFFFF;
	return padding_size;
}

static unsigned long read_padding_size_memory(unsigned char* memory) {
	int ret;
	unsigned long padding_size;

	padding_size = 0;
	memcpy(&padding_size, memory, 4);
	return padding_size;
}

static void set_padding_size(PCRYPT_ALGORITHM crypt, 
							 unsigned long padding_size) {
#if defined(LTC_ECB_MODE) || defined(LTC_CBC_MODE) || defined(LTC_LRW_MODE)
	if ((crypt->mode == ECB_MODE) ||
		(crypt->mode == CBC_MODE) ||
		(crypt->mode == LRW_MODE)) {
		crypt->padding_size = padding_size;
	}
#endif
}

#if 0
static int mode_do_special_stream(PCRYPT_ALGORITHM crypt, FILE* fp) {
	int err;
	switch (crypt->mode) {
#if defined(LTC_LRW_MODE)
	case LRW_MODE:{
		unsigned char tweak[16];
		
		err = fread(tweak, 1, 16, fp);
		if (err != 16)
			return 1;
		memcpy(crypt->tweak, tweak, 16);
	}break;
#endif
	default:
		break;
	}

	return 0;
}

static void mode_do_special_memory(PCRYPT_ALGORITHM crypt, 
								   unsigned char* memory) {
	switch (crypt->mode) {
#if defined(LTC_LRW_MODE)
	case LRW_MODE:
		unsigned char tweak[16];		
		memcpy(crypt->tweak, memory, 16);
		break;
#endif
	default:
		break;
	}
}

static void mode_do_special_reset(PCRYPT_ALGORITHM crypt) {
	switch (crypt->mode) {
	case LRW_MODE:
		
		break;
	default:
		break;
	}
}

#endif

static int mode_start(PCRYPT_ALGORITHM crypt) {
	int err;

 _start:
	switch (crypt->mode) {

#if defined(LTC_ECB_MODE) || defined(LTC_CBC_MODE) || defined(LTC_LRW_MODE)
	case ECB_MODE:
	case CBC_MODE:
	case LRW_MODE:
		if (crypt->mode == ECB_MODE) {
			err = ecb_start(crypt->id, 
							crypt->key, 
							crypt->key_size, 
							0, 
							&(crypt->ecb_key));
		} else if (crypt->mode == CBC_MODE) {
			err = cbc_start(crypt->id, 
							crypt->iv,
							crypt->key, 
							crypt->key_size, 
							0, 
							&(crypt->cbc_key));

		} else if (crypt->mode == LRW_MODE) {
			/*
			if ((err = get_random_number(crypt->prng_id,
										 crypt->tweak, 
										 16)) == -1)
				return CRYPT_ERROR;
			*/
			memcpy(crypt->tweak, "1234567890!@#$%^", 16);
			err = lrw_start(crypt->id,
							crypt->iv,
							crypt->key,
							crypt->key_size,
							crypt->tweak,
							0,
							&(crypt->lrw_key));
		}
		crypt->padding_size = 0;
		memset(crypt->padding_data, 0, 64);
		break;
#endif

#if defined(LTC_CFB_MODE)
	case CFB_MODE:
		err = cfb_start(crypt->id,
						crypt->iv,
						crypt->key,
						crypt->key_size,
						0,
						&(crypt->cfb_key));
		break;
#endif

#if defined(LTC_CTR_MODE)
	case CTR_MODE:
		err = ctr_start(crypt->id,
						crypt->iv,
						crypt->key,
						crypt->key_size,
						0,
						CTR_COUNTER_LITTLE_ENDIAN,
						&(crypt->ctr_key));
		break;
#endif

#if defined(LTC_F8_MODE)
	case F8_MODE: {
		/*
		if ((err = get_random_number(crypt->prng_id, 
									 salt_key, 
									 skeylen)) == -1)
			return CRYPT_ERROR;
		*/
		memcpy(crypt->salt_key, "5-513", 5);
		crypt->skeylen = 5;
		err = f8_start(crypt->id,
					   crypt->iv,
					   crypt->key,
					   crypt->key_size,
					   crypt->salt_key,
					   crypt->skeylen,
					   0,
					   &(crypt->f8_key));
	}break;
#endif

#if defined(LTC_OFB_MODE)
	case OFB_MODE:
		err = ofb_start(crypt->id,
						crypt->iv,
						crypt->key,
						crypt->key_size,
						0,
						&(crypt->ofb_key));
		break;
#endif

#if defined(LTC_XTS_MODE)
	case XTS_MODE:
		memcpy(crypt->tweak, "1234567890!@#$%^", 16);
		err = xts_start(crypt->id,
						crypt->key,
						crypt->xts_tweak_key,
						crypt->key_size,
						0,
						&(crypt->xts_key));
		break;
#endif
	default:
#if defined(LTC_ECB_MODE)
		crypt->mode = ECB_MODE;
#endif
		goto _start;
		break;
	}
	return err;
}

static int mode_restart(PCRYPT_ALGORITHM crypt, unsigned char* IV) {
	int err;
	
	err = reset_iv(crypt, IV);
	err = mode_start(crypt);

	return err;
}

static unsigned long get_align_size(unsigned long len, unsigned long align, CRYPT_MODE mode) {
	unsigned long total_size = 0;

#if defined(LTC_LRW_MODE)
	if (mode == LRW_MODE) {
		total_size = ALIGN_UP(len, 16);
	} else {
		total_size = ALIGN_UP(len, align);
	}
#else	
	total_size = ALIGN_UP(len, align);
#endif
	
	return total_size;
}

static int mode_encrypt(PCRYPT_ALGORITHM crypt, 
						unsigned char* pt, unsigned char* ct,
						unsigned long len) {
	int err;

	crypt->after_encrypted = 1;

 _start:
	switch (crypt->mode) {
#if defined(LTC_ECB_MODE) || defined(LTC_CBC_MODE) || defined(LRW_MODE)
	case ECB_MODE:
	case CBC_MODE:
	case LRW_MODE:{
		unsigned long total_size;
		unsigned char* buffer;
		unsigned char* buffer2;

		total_size = get_align_size(len, crypt->blocklen, crypt->mode);

		buffer = (unsigned char*)malloc(total_size);
		buffer2 = (unsigned char*)malloc(total_size);
		memset((void*)buffer, 0, total_size);
		memset((void*)buffer2, 0, total_size);
		memcpy(buffer, pt, len);
		
		if (crypt->mode == ECB_MODE) {
			err = ecb_encrypt(buffer, buffer2, total_size, &(crypt->ecb_key));
		} else if (crypt->mode == CBC_MODE) {
			err = cbc_encrypt(buffer, buffer2, total_size, &(crypt->cbc_key));
		} else if (crypt->mode == LRW_MODE) {
			err = lrw_encrypt(buffer, buffer2, total_size, &(crypt->lrw_key));
		}

		/* 加密成功 */
		if (err == CRYPT_OK) {
			memcpy(ct, buffer2, len);
			crypt->padding_size = total_size - len;

			/* 进行填充物填充 */
			if (crypt->padding_size) {
				memcpy(crypt->padding_data, 
					   buffer2 + len, 
					   crypt->padding_size);
			}
		}

		free(buffer);
		free(buffer2);
	}break;
#endif

#if defined(LTC_CFB_MODE)
	case CFB_MODE:
		err = cfb_encrypt(pt, ct, len, &(crypt->cfb_key));
		break;
#endif

#if defined(LTC_CTR_MODE)
	case CTR_MODE:
		err = ctr_encrypt(pt, ct, len, &(crypt->ctr_key));
		break;
#endif

#if defined(LTC_F8_MODE)
	case F8_MODE:
		err = f8_encrypt(pt, ct, len, &(crypt->f8_key));
		break;
#endif

#if defined(LTC_OFB_MODE)
	case OFB_MODE:
		err = ofb_encrypt(pt, ct, len, &(crypt->ofb_key));
		break;
#endif

#if defined(LTC_XTS_MODE)
	case XTS_MODE:
		err = xts_encrypt(pt, len, ct, 
						  crypt->xts_tweak_key,
						  &(crypt->xts_key));
		break;
#endif
	default:

#if defined(LTC_ECB_MODE)
		crypt->mode = ECB_MODE;
#endif
		goto _start;
		break;
	}

	return err;
}

static int mode_decrypt(PCRYPT_ALGORITHM crypt,
						unsigned char* ct, unsigned char* pt,
						unsigned long len) {
	int err;

	crypt->after_encrypted = 0;

 _start:
	switch (crypt->mode) {
#if defined(LTC_ECB_MODE)
	case ECB_MODE:{
		err = ecb_decrypt(ct, pt, len, &(crypt->ecb_key));
	}break;
#endif

#if defined(LTC_CBC_MODE)
	case CBC_MODE:
		err = cbc_decrypt(ct, pt, len, &(crypt->cbc_key));
		break;
#endif

#if defined(LTC_CFB_MODE)
	case CFB_MODE:
		err = cfb_decrypt(ct, pt, len, &(crypt->cfb_key));
		break;
#endif

#if defined(LTC_CTR_MODE)
	case CTR_MODE:
		err = ctr_decrypt(ct, pt, len, &(crypt->ctr_key));
		break;
#endif

#if defined(LTC_F8_MODE)
	case F8_MODE:
		err = f8_decrypt(ct, pt, len, &(crypt->f8_key));
		break;
#endif

#if defined(LTC_LRW_MODE)
	case LRW_MODE:
		err = lrw_decrypt(ct, pt, len, &(crypt->lrw_key));
		break;
#endif

#if defined(LTC_OFB_MODE)
	case OFB_MODE:
		err = ofb_decrypt(ct, pt, len, &(crypt->ofb_key));
		break;
#endif

#if defined(LTC_XTS_MODE)
	case XTS_MODE:
		err = xts_decrypt(ct, len, 
						  pt, crypt->xts_tweak_key,
						  &(crypt->xts_key));
		break;
#endif
	default:
#if defined(LTC_ECB_MODE)
		crypt->mode = ECB_MODE;
#endif
		goto _start;
		break;
	}

	return err;
}

static int mode_done(PCRYPT_ALGORITHM crypt) {
	int err;

 _start:
	switch (crypt->mode) {
#if defined(LTC_ECB_MODE) || defined(LTC_CBC_MODE) || defined(LTC_LRW_MODE)
	case ECB_MODE:
	case CBC_MODE:
	case LRW_MODE:{
		// 填充物不为0，则改写结果头
		if (crypt->after_encrypted) {
			/* 加密过后 */
			unsigned char* tmp;
			tmp = (unsigned char*)malloc(crypt->result_size);
			memcpy(tmp, crypt->result, crypt->result_size);
			free(crypt->result);

			crypt->result_size = crypt->result_size + 4 + crypt->padding_size;
			crypt->result = (unsigned char*)malloc(crypt->result_size);

			memcpy(crypt->result, (void*)&(crypt->padding_size), 4);
			memcpy(crypt->result + 4, tmp, 
				   crypt->result_size - 4 - crypt->padding_size);

			if (crypt->padding_size) {
				memcpy(crypt->result + crypt->result_size - crypt->padding_size,
					   crypt->padding_data,
					   crypt->padding_size);
			}
			free(tmp);
		} else {
			crypt->result_size -= crypt->padding_size;
		}
		if (crypt->mode == ECB_MODE)
			err = ecb_done(&(crypt->ecb_key));
		else if (crypt->mode == CBC_MODE)
			err = cbc_done(&(crypt->cbc_key));
		else if (crypt->mode == LRW_MODE)
			err = lrw_done(&(crypt->lrw_key));
	}break;
#endif

#if defined(LTC_CFB_MODE)
	case CFB_MODE:
		err = cfb_done(&(crypt->cfb_key));
		break;
#endif

#if defined(LTC_CTR_MODE)
	case CTR_MODE:
		err = ctr_done(&(crypt->ctr_key));
		break;
#endif

#if defined(LTC_F8_MODE)
	case F8_MODE:
		err = f8_done(&(crypt->f8_key));
		break;
#endif

#if defined(LTC_OFB_MODE)
	case OFB_MODE:
		err = ofb_done(&(crypt->ofb_key));
		break;
#endif

#if defined(LTC_XTS_MODE)
	case XTS_MODE:
		xts_done(&(crypt->xts_key));
		break;
#endif
	default:
#if defined(LTC_ECB_MODE)
		crypt->mode = ECB_MODE;
#endif
		goto _start;
		break;
	}

	return err;
}

int cryptInit() {
	int err;
   
#ifdef LTC_RIJNDAEL
	register_cipher (&aes_desc);
#endif
#ifdef LTC_BLOWFISH
	register_cipher (&blowfish_desc);
#endif
#ifdef LTC_XTEA
	register_cipher (&xtea_desc);
#endif
#ifdef LTC_RC5
	register_cipher (&rc5_desc);
#endif
#ifdef LTC_RC6
	register_cipher (&rc6_desc);
#endif
#ifdef LTC_SAFERP
	register_cipher (&saferp_desc);
#endif
#ifdef LTC_TWOFISH
	register_cipher (&twofish_desc);
#endif
#ifdef LTC_SAFER
	register_cipher (&safer_k64_desc);
	register_cipher (&safer_sk64_desc);
	register_cipher (&safer_k128_desc);
	register_cipher (&safer_sk128_desc);
#endif
#ifdef LTC_RC2
	register_cipher (&rc2_desc);
#endif
#ifdef LTC_DES
	register_cipher (&des_desc);
	register_cipher (&des3_desc);
#endif
#ifdef LTC_CAST5
	register_cipher (&cast5_desc);
#endif
#ifdef LTC_NOEKEON
	register_cipher (&noekeon_desc);
#endif
#ifdef LTC_SKIPJACK
	register_cipher (&skipjack_desc);
#endif
#ifdef LTC_KHAZAD
	register_cipher (&khazad_desc);
#endif
#ifdef LTC_ANUBIS
	register_cipher (&anubis_desc);
#endif


	return CRYPT_OK;
}

PCRYPT_ALGORITHM cryptAlloc(int id, int mode, int hash_id, int prng_id, char* key_string) {
	int err;
	unsigned long outlen;
	PCRYPT_ALGORITHM p;
	
	if ((find_cipher_id(id) == -1) || 
		(find_hash_id(hash_id) == -1) ||
		(find_prng_id(prng_id) == -1)) {
		return NULL;
	}

	p = (PCRYPT_ALGORITHM)malloc(sizeof(CRYPT_ALGORITHM));
	memset((void*)p, 0, sizeof(CRYPT_ALGORITHM));
	p->id = find_cipher_id(id);
	p->hash_id = find_hash_id(hash_id);
	p->prng_id = find_prng_id(prng_id);
	p->mode = mode;
	p->key_size = hash_descriptor[hash_id].hashsize;
	p->blocklen = cipher_descriptor[id].block_length;

#if defined(LTC_XTS_MODE)
	if (id == XTS_MODE) p->xts_tweak_size = p->key_size;
	else p->iv_size = cipher_descriptor[p->id].block_length;
#else
	p->iv_size = cipher_descriptor[p->id].block_length;
#endif

	if (cipher_descriptor[id].keysize(&(p->key_size)) != CRYPT_OK) {
		free(p);
		return NULL;
	}

	outlen = sizeof(p->key);
	if ((err = hash_memory(hash_id, (unsigned char*)key_string, strlen(key_string), p->key, &outlen)) != CRYPT_OK) {
		free(p);
		return NULL;
	}

	if ((err = get_iv(p)) != CRYPT_OK) {
		free(p);
		return NULL;
	}

	if ((err = mode_start(p)) != CRYPT_OK) {
		free(p);
		return NULL;
	}
	
	p->result_size = 0;
	p->result = NULL;

	return p;
}

void cryptFree(PCRYPT_ALGORITHM crypt) {
	mode_done(crypt);
	if ((crypt->result_size) && (crypt->result)) {
		free(crypt->result);
		memset(crypt, 0, sizeof(CRYPT_ALGORITHM));
	}

	free(crypt);
}

#define _close_crypt_io()		if (fdin != stdin) fclose(fdin); 
#define _return_error()			return err;
int cryptRun(PCRYPT_ALGORITHM crypt, int from_stdin, int encrypt, char* file) {
	int err, y, x;
	unsigned long padding_size;
	unsigned char plaintext[512], ciphertext[512];
	unsigned char IV[MAXBLOCKSIZE];
	unsigned char inbuf[512];	/* i/o block size */
	prng_state prng;
	FILE* fdin;

	x = 0;             /* 后面有用 */
	if (from_stdin) {
		fdin = stdin;
	} else {
		fdin = fopen(file, "rb");
		if (fdin == NULL)
			return CRYPT_ERROR;
		/* 得到文件大小 */
		//fseek(fdin, 0, SEEK_END);
		//x = ftell(fdin);
		//fseek(fdin, 0, SEEK_SET);
	}

	if (!encrypt) {/* 解密 */
		
		if (has_padding(crypt->mode)) {
			/* 读取填充物大小 */
			padding_size = read_padding_size_stream(fdin);
			if (padding_size == 0xFFFFFFFF) {
				_close_crypt_io();
				return CRYPT_ERROR;
			}
			set_padding_size(crypt, padding_size);
		}

		if (has_iv(crypt->mode)) {
			/* 读取IV值 */
			if ((int)fread(IV, 1, crypt->iv_size, fdin) != crypt->iv_size) {
				_close_crypt_io();	
				return CRYPT_ERROR;
			}

#if defined(DEBUG)
			print_iv(IV, crypt->iv_size);
			print_key(crypt->key, crypt->key_size);
#endif   
			if ((err = reset_iv(crypt, IV)) != CRYPT_OK) {
				_close_crypt_io();
				return err;
			}
		}

#if 0
		/* 模式特殊操作 */
		if ((err = mode_do_special_stream(crypt)) != 0) {
			_close_crypt_io();
			_return_error();
		}
#endif
		/* IV done */
		x = 0;
		do {
			y = fread(inbuf, 1, sizeof(inbuf), fdin);

			if ((err = mode_decrypt(crypt,
									inbuf, 
									plaintext, 
									y)) != CRYPT_OK) {
				_return_error();
			}

			/* 如果是第一轮则分配内存 */
			if (crypt->result == NULL) {
				crypt->result = (unsigned char*)malloc(y);
				memcpy(crypt->result, plaintext, y);
			} else {
				unsigned char* tmp = (unsigned char*)malloc(x);
				memcpy(tmp, crypt->result, x);
				free(crypt->result);
				crypt->result = (unsigned char*)malloc(x+y);
				memcpy(crypt->result, tmp, x);
				memcpy(crypt->result+x, plaintext, y);
				free(tmp);
			}

			x += y;

		} while (y == sizeof(inbuf));
		crypt->result_size = x;
		_close_crypt_io();
	} else {/* 加密 */  

		if (has_iv(crypt->mode)) {
			crypt->result = (unsigned char*)malloc(crypt->iv_size);
			memcpy(crypt->result, crypt->iv, crypt->iv_size);		/* 初始值 */

#if defined(DEBUG)
			print_iv(crypt->iv, crypt->iv_size);
			print_key(crypt->key, crypt->key_size);
#endif

			x = crypt->iv_size;
		} else {
			crypt->result = NULL;
			x = 0;
		}
		do {
			y = fread(inbuf, 1, sizeof(inbuf), fdin);

			if ((err = mode_encrypt(crypt,
									inbuf, 
									ciphertext, 
									y)) != CRYPT_OK) {
				_close_crypt_io();
				_return_error();
			} else {
				/* 如果没有IV值则这里result为NULL */
				if (!crypt->result) {
					crypt->result = (unsigned char*)malloc(y);
					memcpy(crypt->result, ciphertext, y);
				} else {
					unsigned char* tmp = (unsigned char*)malloc(x);
					memcpy(tmp, crypt->result, x);
					free(crypt->result);
					crypt->result = (unsigned char*)malloc(x+y);
					memcpy(crypt->result, tmp, x);
					memcpy(crypt->result+x, ciphertext, y);
					free(tmp);
				}/* end else */
			}/* end else */

			x += y;

		} while (y == sizeof(inbuf));
		crypt->result_size = x;
		_close_crypt_io();
	}

	mode_done(crypt);

	return CRYPT_OK;
}

int cryptRun2(PCRYPT_ALGORITHM crypt, int encrypt, unsigned char* buffer, unsigned long size) {
	int err, rsize, x;
	symmetric_CTR ctr;
	unsigned char* inbuf;
	unsigned char* plaintext;
	unsigned char* ciphertext;
	unsigned char IV[MAXBLOCKSIZE];
	unsigned long padding_size;

	LTC_ARGCHK(crypt != NULL);
	LTC_ARGCHK(buffer != NULL);
	LTC_ARGCHK(size > 0);

	if (!encrypt) {/* 解密 */
		/* 读取padding size */
		if (has_padding(crypt->mode)) {
			padding_size = read_padding_size_memory(buffer);
			inbuf = buffer + 4;
			rsize = size - 4;
		} else {
			inbuf = buffer;
			rsize = size;
		}

		/* 读取IV值 */
		if (size <= crypt->iv_size)
			return CRYPT_ERROR;

		memcpy(IV, inbuf, crypt->iv_size);
		inbuf += crypt->iv_size;
		rsize -= crypt->iv_size;

#if defined(DEBUG)
		print_iv(IV, crypt->iv_size);
		print_key(crypt->key, crypt->key_size);
#endif
		
		plaintext = (unsigned char*)malloc(size);
		if (!plaintext)
			return CRYPT_ERROR;

		if (has_iv(crypt->mode)) {

			/* 重新设置IV值 */
			if ((err = reset_iv(crypt, IV)) != CRYPT_OK) {
				free(plaintext);
				_return_error();
			}
		}

		if ((err = mode_decrypt(crypt,
								inbuf, 
								plaintext, 
								rsize)) != CRYPT_OK) {
			_return_error();
		}

		/* 如果是第一轮则分配内存 */
		if (crypt->result == NULL) {
			crypt->result = (unsigned char*)malloc(rsize);
			memcpy(crypt->result, plaintext, rsize);
			free(plaintext);
		}
		crypt->result_size = rsize;
	} else {/* 加密 */
		int offset;
		if (has_iv(crypt->mode)) {
			crypt->result = (unsigned char*)malloc(crypt->iv_size + size);		        /* IV值长度 + 数据长度 */

#if defined(DEBUG)
			print_iv(crypt->iv, crypt->iv_size);
			print_key(crypt->key, crypt->key_size);
#endif
			memcpy(crypt->result, crypt->iv, crypt->iv_size);					        /* 初始值 */
			offset = crypt->iv_size;
		} else {
			crypt->result = (unsigned char*)malloc(size);		                        /* IV值长度 + 数据长度 */
			offset = 0;
		}
		
		inbuf = buffer;
		ciphertext = (unsigned char*)malloc(size);
		if (!ciphertext)
			return CRYPT_ERROR;

		if ((err = mode_encrypt(crypt,
								inbuf, 
								ciphertext, 
								size)) != CRYPT_OK) {
			free(ciphertext);
			_return_error();
		}

		memcpy(crypt->result + offset, ciphertext, size);
		crypt->result_size = size + offset;
		free(ciphertext);
	}

	mode_done(crypt);

	return CRYPT_OK;
}

void cryptPrintAlgorithm(int print_id) {
	int x = 0;

#if 0
	for (x = 0; cipher_descriptor[x].name != NULL; x++) {
		if (print_id)
			printf("%d %d %s\n", cipher_descriptor[x].ID,
				   cipher_descriptor[x].block_length,
				   cipher_descriptor[x].name);
		else
			printf("%s\n", cipher_descriptor[x].name);
	}
#endif

	for (x = 0; x < TAB_SIZE; x++) {
		if (cipher_descriptor[x].name != NULL) {
			if (print_id)
				printf("%d %d %s\n", cipher_descriptor[x].ID,
					   cipher_descriptor[x].block_length,
					   cipher_descriptor[x].name);
			else
				printf("%s\n", cipher_descriptor[x].name);
		}
	}
			
}

void cryptPrintResult(PCRYPT_ALGORITHM crypt, int text) {
	unsigned long x;
	if (!text) {
		for (x = 0; x < crypt->result_size; x++) {
			printf("%02x", crypt->result[x]);
		}
		printf("\n");
	} else {
		for (x = 0; x < crypt->result_size; x++) {
			printf("%c", crypt->result[x]);
		}
		printf("\n");
	}
}

void cryptPrintMode(int print_id) {
	int i;
	for (i = 0; i < MAX_CRYPT_MODE; i++) {
		if (print_id)
			printf("%d %s\n", i, g_crypt_mode_string[i]);
		else
			printf("%s\n", g_crypt_mode_string[i]);
	}
	printf("\n");
}
