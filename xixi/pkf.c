#include "pkf.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#include <uuid/uuid.h>

static char* g_nanan_path = NULL;

static char* g_hash_algorithm[] = {
	"sha256",
	"tiger",
	"sha1",
	"md5",
	"sha384",
	"sha512",
	"md4",
	"md2",
	"rmd128",
	"rmd160",
	"sha224",
	"whirlpool",
	"chc_hash"
};

static char* g_sign_algorithm[] = {
	"rsa",
	"ecc",
	"dsa",
	"dh"
};

static char* g_prng_algorithm[] = {
	"yarrow",
	"sprng",
	"sober128",
	"fortuna",
	"rc4"
};

static char* g_crypt_algorithm[] = {
	"blowfish",
	"xtea",
	"rc5",
	"rc6",
	"safer+",
	"NULL",
	"aes",
	"twofish",
	"safer-k64",
	"safer-sk64",
	"safer-k128",
	"safer-sk128",
	"rc2",
	"des",
	"3des",
	"cast5",
	"noekeon",
	"skipjack",
	"khazad",
	"anubis"
};

#include "tools.h"
#include "pkf_tools.h"
#include "pkf_show.h"

void pkfShow(PPKF pkf) {
	show_pkf(pkf);
}

#define _fill_pkf_header(h)						\
	(h)->magic = PKF_MAGIC;						\
	   (h)->version = PKF_VERSION;				\
		  uuid_generate((h)->pkf_id);

#define DEF_PKF_PASSWORD            "aSBsb3ZlIHlvdSB4aWFvcWlhbiBmb3IgZXZlcgo="
PPKF pkfAlloc(int hash_id, 
			  int sign_id, 
			  int prng_id,
			  char* email, 
			  char* organ,
			  unsigned int end_time,
			  char* password, 
			  int crypt_id) {
	PPKF pkf;
	time_t the_time;

	pkf = (PPKF)malloc(sizeof(PKF));
	if (!pkf) return NULL;
	memset((void*)pkf, 0, sizeof(PKF));

	_fill_pkf_header(pkf);

	pkf->sign_support.hash_id = hash_id;
	pkf->sign_support.sign_id = sign_id;
	pkf->sign_support.prng_id = prng_id;
	strcpy(pkf->email, email);
	strcpy(pkf->organization, organ);

	time((time_t*)&(pkf->begin_time));
	pkf->end_time = end_time;

	/* 查看是否密码为空 */
	if (!strlen(password)) {
		strcpy(pkf->password, DEF_PKF_PASSWORD);
	} else {
		strcpy(pkf->password, password);
	}
	pkf->crypt_id = crypt_id;

	return pkf;
}

void pkfFree(PPKF_V1 pkf) {
	if (pkf)
		free(pkf);
}

int pkfMakeKeyPair(char* public_key_path,
				   char* private_key_path) {
	int err;
	char buffer[128] = {0};

#if 0
	unsigned char* private_key;
	unsigned long private_key_size;
	unsigned char* public_key;
	unsigned long public_key_size;

	private_key = NULL;
	private_key_size = 0;
	public_key = NULL;
	public_key_size = 0;
#endif

	//err = execl(g_nanan_path, "nanan", "-m", ".", NULL);
	sprintf(buffer, "%s --silent -m .", g_nanan_path);
	system(buffer);

#if 0
	if (private_key_path) {

		err = read_file("./private.key", 
						&private_key,
						&private_key_size);
		if (err != 0)
			goto _error;

		err = write_file(private_key_path, 
						 private_key, 
						 private_key_size);
		if (err != 0)
			goto _error;
	}

	if (public_key_path) {
		err = read_file("./public.key", 
						&public_key,
						&public_key_size);
		if (err != 0)
			goto _error;

		err = write_file(public_key_path, 
						 public_key, 
						 public_key_size);
		if (err != 0)
			goto _error;
	}
#endif

 _error:
	//delete_file("./private.key");
	//delete_file("./public.key");
#if 0
	if (private_key) free(private_key);
	if (public_key) free(public_key);
#endif
	return 0;
}

#define freev(v)  free(v);v=NULL;
/**
 * @brief 生成PKF证书
 * @param pkf 指向一个pkf证书指针
 * @param make_key 是否生成公私钥对
 * @param public_key_path 公钥路径
 * @param private_key_path 私钥路径
 * @paran g_nanan_path 我的爱狗
 */
PPKF pkfMake(PPKF pkf, 
			 int make_key, 
			 char* public_key_path,
			 char* private_key_path) {
	int err, t, size;
	char buffer[256];
	unsigned char* tmp;
	char password[512];
	int crypt_id;
	unsigned char* value;
	unsigned long value_size;

	t = 0;    /* 底下要用 */
	memset(buffer, 0, 256);

	crypt_id = pkf->crypt_id;
	strcpy(password, pkf->password);

	if (make_key) {
		/*
		 * 生成公私钥对
		 */
		err = pkfMakeKeyPair(public_key_path,
							 private_key_path);
		if (err != 0)
			goto _error;
	}

	tmp = (unsigned char*)malloc(10240);
	memset(tmp, 0, 10240);

	/* 私钥不为空 */
	if (private_key_path || strlen(private_key_path)) {
		unsigned char* private_key;
		PKF_PRIVATE_KEY_SECURITY security;

		pkf->property |= PKF_PROP_PRIVATE;

		if (strlen(password)) {
			security.crypt_id = crypt_id;
			memcpy(tmp, &security, sizeof(PKF_PRIVATE_KEY_SECURITY));
			t = sizeof(PKF_PRIVATE_KEY_SECURITY);
			pkf ->property |= PKF_PROP_DECRYPT_PRIVATE;	

			private_key = tmp + t;

			/*
			 * 使用密码进行加密并输出到当前目录
			 */
			err = crypt_file(g_nanan_path,
							 private_key_path,
							 security.crypt_id,
							 2,
							 1,
							 password,
							 &value,
							 &value_size);

			if (err != 0) {
				goto _error;
			}

			memcpy(private_key, value, value_size);
			pkf->private_key_size = value_size;
			t += value_size;
			freev(value);

			/* 计算密码的SHA1值 */
			err = hash_string(g_nanan_path, 
							  password, 
							  2, 
							  &value, 
							  &value_size);
			if (err != 0) {
				goto _error;
			}
			memcpy(pkf->password_hash, value, value_size);
			freev(value);
		} else {
			err = read_file(private_key_path, &value, &value_size);
			if (err != 0)
				goto _error;

			private_key = tmp;
			memcpy(private_key, value, value_size);
			pkf->private_key_size = value_size;
			t += value_size;
			freev(value);
		}/* end else */
	}

	/* 公钥不为空 */
	if (public_key_path || strlen(public_key_path)) {
		unsigned char* public_key;

		pkf->property |= PKF_PROP_PUBLIC;

		public_key = tmp + t;
		
		err = read_file(public_key_path, &value, &value_size);
		if (err != 0)
			goto _error;

		memcpy(public_key, value, value_size);
		pkf->public_key_size = value_size;
		t += value_size;
		freev(value);
	}

	/* 由于是新建证书,没有办法者，所以这里算作是根证书 */
	pkf->property |= PKF_PROP_ROOT;

	/* 计算PKF证书总长度 */
	pkf->file_size = sizeof(PKF) + t;

	/* 重新设定证书 */
	{
		unsigned char* tmp2;
		unsigned char* checksum_data;

		tmp2 = (unsigned char*)malloc(pkf->file_size);
		if (!tmp2) {
			goto _error;
		}

		memcpy(tmp2, (unsigned char*)pkf, sizeof(PKF));
		memcpy(tmp2+sizeof(PKF), tmp, t);

		free(pkf);
		free(tmp);

		pkf = (PPKF)tmp2;
		
		/* 计算校验和 */
		if (checksum_file(pkf) != 0) {
			goto _error;
		}
	}

	return pkf;
 _error:
	if (tmp) free(tmp);
	if (pkf) free(pkf);
	return NULL;
}

PPKF pkfSign(char* pkf_file, 
			 char* opk_file, 
			 PPKF_ISSUER issuer) {
	PPKF pkf;
	char buffer[512];
	unsigned char* value;
	unsigned long value_size;
	unsigned char* sign_data;
	int err, sign_size;
	unsigned char* tmp;

	pkf = NULL;
	tmp = NULL;

	err = read_file(pkf_file, &value, &value_size);
	if (err != 0) {
		goto _error;
	}

	tmp = (unsigned char*)malloc(value_size+4096);/* 多分配4KB */
	if (!tmp) {
		goto _error;
	}
	memcpy(tmp, value, value_size);
	pkf = (PPKF)tmp;

	/* 签名需要公钥存在 */
	if (pkf->property & PKF_PROP_PUBLIC == 0) {
		goto _error;
	}
	
	/* 需要签名的内容就是在checksum以下的内容 */
	sign_data = (unsigned char*)&(pkf->sign_start);
	sign_size = pkf->file_size - (int)(sign_data - tmp);
	
	if (sign_size <= 0) {
		goto _error;
	}

	/* 计算公钥签名 */
	{
		char tmpfile[256];
		unsigned char* tmp_sign;
		unsigned long tmp_sign_size;

		srand(0);
		sprintf(tmpfile, ".sign_pkf_%d", rand());
		err = write_file(tmpfile, sign_data, sign_size);
		if (err != 0) {
			goto _error;
		}

		err = sign_file(g_nanan_path,
						tmpfile,
						pkf->sign_support.sign_id,
						pkf->sign_support.hash_id,
						pkf->sign_support.prng_id,
						opk_file,
						&tmp_sign,
						&tmp_sign_size);
		if (err != 0) {
			goto _error;
		}

		sign_data = tmp + pkf->file_size;
		memcpy(sign_data, tmp_sign, tmp_sign_size);
		free(tmp_sign);
		delete_file(tmpfile);
	
		/* 设置颁发者签名信息 */
		issuer->sign_size = tmp_sign_size;
		memcpy((unsigned char*)&(pkf->issuer),
			   issuer,
			   sizeof(PKF_ISSUER));

		/* 这里取消掉根证书的属性 */
		pkf->property &= ~PKF_PROP_ROOT;

		/* 写入签名属性 */
		pkf->property |= PKF_PROP_SIGN;

		/* 重新计算PKF文件长度 */
		pkf->file_size += tmp_sign_size;
	}

	/* 重新计算校验和 */
	if ((err = checksum_file(pkf))!= 0) {
		goto _error;
	}

	{
		/* 重新写入到文件中 */
		char new_file[256];

		sprintf(new_file, 
				"%s.sign",
				pkf_file);
		err = write_file(new_file, 
						 (unsigned char*)pkf,
						 pkf->file_size);
		if (err != 0)
			goto _error;
	}
	if (value) free(value);
	return pkf;
 _error:
	if (tmp) free(tmp);
	if (value) free(value);
	return NULL;
}

int pkfVerify(char* pkf_file, 
			  char* opp_file,
			  int* result) {
	int err;
	PPKF pkf;
	unsigned char* tmp;
	unsigned long pkf_size;
	unsigned char* sign_data;
	unsigned long sign_data_size;
	unsigned char* sign;
	unsigned long sign_size;
	char tmpfile[256];
	char tmpfile2[256];

	tmp = NULL;
	pkf_size = 0;

	err = read_file(pkf_file, &tmp, &pkf_size);
	if (err != 0) {
		goto _error;
	}
	
	pkf = (PPKF)tmp;

	/* 首先检查证书是否过期 */
#if 0
	{
		time_t now;
		time(&now);
		if (difftime(pkf->end_time, 
					 now) > 0) {
			*result = 0;
			free(tmp);
			return 0;
		}/* end if */
	}
#endif

	/* 需要签名的内容就是在checksum以下的内容 */
	sign_data = (unsigned char*)&(pkf->sign_start);
	sign_data_size = pkf->file_size - (int)(sign_data - tmp);
	
	if (sign_data_size <= 0) {
		goto _error;
	}

	srand(0);
	sprintf(tmpfile, ".verify_%d", rand());

	err = write_file(tmpfile, sign_data, sign_data_size);
	if (err != 0) {
		goto _error;
	}

	/* 读取签名 */
	sign = get_sign(pkf);
	if (!sign) {
		err = 2;
		goto _error;
	}
	sign_size = pkf->file_size - (sign - tmp);

	sprintf(tmpfile2, ".sign_data_%d", rand());
	
	err = write_file(tmpfile2, sign, sign_size);
	if (err != 0)
		goto _error;

	err = verify_file(g_nanan_path,
					  tmpfile,
					  pkf->sign_support.sign_id,
					  pkf->sign_support.hash_id,
					  pkf->sign_support.prng_id,
					  opp_file,
					  tmpfile2,
					  (unsigned char*)result);
	if (err != 0)
		goto _error;

	err = 0;
   
 _error:
	if (tmp) free(tmp);
	delete_file(tmpfile);
	delete_file(tmpfile2);
	return err;
}

void pkfSetNanan(char* nanan_path) {
	g_nanan_path = nanan_path;
}

int pkfReadPrivateKey(char* opk_file, 
					  char* private_out_file,
					  char* password) {
	int err;
	unsigned char* value;
	unsigned long value_size;
	PPKF pkf;
	unsigned char* _private_key;
	unsigned long _private_key_size;
	unsigned char* hash;
	unsigned long hash_size;
	char tmpfile[256];
	unsigned char* private_key;
	unsigned long private_key_size;
	unsigned char* x;
	unsigned long y;

	value = NULL;
	value_size = 0;
	
	err = read_file(opk_file, &value, &value_size);
	if (err != 0) { 
		goto _error;
	}

	pkf = (PPKF)value;

	/* 判断当前PKF是否存在私钥 */
	if (pkf->property & PKF_PROP_PRIVATE == 0) {
		goto _error;
	}
	
	_private_key = get_private_key(pkf);
	if (_private_key == NULL)
		goto _error;
	_private_key_size = pkf->private_key_size;

	/* 如果私钥没有加密则直接跳过加密过程 */
	if (pkf->property & PKF_PROP_DECRYPT_PRIVATE == 0) {
		x = _private_key;
		y = _private_key_size;
		goto _write_private_key;
	}

	/* 开始解密 */
	err = hash_string(g_nanan_path,
					  password,
					  2,
					  &hash,
					  &hash_size);
	if (err != 0) {
		goto _error;
	}

	if (memcmp(hash, pkf->password_hash, hash_size) != 0) {
		goto _error;
	}

	srand(0);
	sprintf(tmpfile, ".decrypt_private_key_%d", rand());
	err = write_file(tmpfile, _private_key, _private_key_size);
	if (err != 0) {
		goto _error;
	}

	err = crypt_file(g_nanan_path,
					 tmpfile,
					 6,
					 2,
					 0,
					 password,
					 &private_key,
					 &private_key_size);
	if (err != 0)
		goto _error;

	x = private_key;
	y = private_key_size;

 _write_private_key:
	sprintf(private_out_file, 
			".tmp_prikey_%d", 
			rand());
	err = write_file(private_out_file, 
					 x, 
					 y);
   

	if (err != 0)
		goto _error;

 _error:
	if (value) free(value);
	delete_file(tmpfile);
	return err;

}

int pkfReadPublicKey(char* opk_file, 
					 char* public_out_file) {
	int err;
	unsigned char* value;
	unsigned long value_size;
	unsigned char* public_key;
	unsigned long public_key_size;
	PPKF pkf;

	err = 0;
	value = NULL;
	value_size = 0;
	pkf = NULL;

	err = read_file(opk_file, &value, &value_size);
	if (err != 0) {
		goto _error;
	}

	pkf = (PPKF)value;

	if (pkf->property & PKF_PROP_PUBLIC == 0) {
		err = 1;
		goto _error;
	}

	public_key = get_public_key(pkf);
	public_key_size = pkf->public_key_size;
	if (public_key) {
		srand(0);
		sprintf(public_out_file, 
				".tmp_pubkey_%d", rand());
		err = write_file(public_out_file,
						 public_key,
						 public_key_size);
		if (err != 0) {
			goto _error;
		}
	} else {
		err = 1;
		goto _error;
	}

 _error:
	if (value) free(value);
	return err;
}

int pkfReadIssuer(char* opk_file, PPKF_ISSUER issuer) {
	int err;
	unsigned char* value;
	unsigned long value_size;
	PPKF pkf;

	value = NULL;
	value_size = 0;

	err = read_file(opk_file, &value, &value_size);
	if (err != 0) {
		goto _error;
	}

	pkf = (PPKF)value;

	memcpy(issuer->pkf_id, pkf->pkf_id, sizeof(XID));
	strcpy(issuer->name, pkf->organization);

 _error:
	if (value) free(value);
	return err;
}
