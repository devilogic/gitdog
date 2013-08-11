#include "pkf.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#include <uuid/uuid.h>

static char* g_hash_algorithm[] = {
	"sha256",
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
	"rc4",
	"fortuna"
};

static char* g_crypt_algorithm[] = {
	"blowfish",
	"xtea",
	"rc5",
	"rc6",
	"safer+",
	"none"
	"aes",
	"twofish",
	"safer-k64",
	"safer-sk64",
	"safer-k128",
	"safer-sk128",
	"rc2",
	"des"
};

static void show_xid(XID xid) {
	int i;
	for (i = 0; i < 16; i++)
		printf("%02x", xid[i]);
	printf("\n");
	return;
}

static char* show_hash(int hash_id) {
	return g_hash_algorithm[hash_id];
}

static char* show_sign(int sign_id) {
	return g_sign_algorithm[sign_id];
}

static char* show_prng(int prng_id) {
	return g_prng_algorithm[prng_id];
}

static char* show_crypt(int crypt_id) {
	return g_crypt_algorithm[crypt_id];
}

static void show_key(unsigned char* key, unsigned int size) {
	unsigned int i;
	for(i = 0; i < size; i++) {
		printf("%02x", key[i]);
	}
	printf("\n");
}

static unsigned char* get_crypt_private_key_struct(PPKF pkf) {
	unsigned char* p;
	p = (unsigned char*)pkf;

	if (pkf->property & PKF_PROP_DECRYPT_PRIVATE)
		p += sizeof(PKF);
	else return NULL;

	return p;
}

static unsigned char* get_private_key(PPKF pkf) {
	unsigned char* p;
	if (pkf->property & PKF_PROP_DECRYPT_PRIVATE) {
		p = get_crypt_private_key_struct(pkf);
		p += sizeof(PKF_PRIVATE_KEY_SECURITY);
	} else {
		p = (unsigned char*)pkf;
		p += sizeof(PKF_PRIVATE_KEY_SECURITY);
	}

	return p;
}

static unsigned char* get_public_key(PPKF pkf) {
	unsigned char*p;
	p = get_private_key(pkf);
	p += pkf->private_key_size;
	return p;
}

static void show_issuer(PPKF pkf) {
	PPKF_ISSUER issuer;
	unsigned char* key;

	issuer = &(pkf->issuer);
	printf("ISSUER XID = "); 
	show_xid(issuer->pkf_id);
	printf("ISSUER NAME = %s\n", issuer->name);
	printf("SIGN SIZE = %d\n", issuer->sign_size);
	
	key = ((char*)pkf) + sizeof(PKF) + 
		pkf->public_key_size + pkf->private_key_size;
	show_key(key, issuer->sign_size);
}

static int show_property(PPKF pkf) {
	unsigned int property;
	unsigned char* key;
	PPKF_PRIVATE_KEY_SECURITY security;

	property = pkf->property;

	if (property & PKF_PROP_PUBLIC) {
		printf("PUBLIC KEY SIZE = %d\n", pkf->public_key_size);
		key = get_public_key(pkf);
		show_key(key, pkf->public_key_size);
	}

	if (property & PKF_PROP_PRIVATE) {
		printf("PRIVATE KEY SIZE = %d\n", pkf->private_key_size);
		key = get_private_key(pkf);
		show_key(key, pkf->private_key_size);
	}

	if (property & PKF_PROP_DECRYPT_PRIVATE) {
		int i;
		security = (PPKF_PRIVATE_KEY_SECURITY)get_crypt_private_key_struct(pkf);
		printf("CRYPT PRIVATE KEY ALGORITHM = %s\n", 
			   show_crypt(security->crypt_id));
		printf("CRYPT PRIVATE KEY PASSWORD SHA1 = ");
		for (i = 0; i < 16; i++)
			printf("%02x", pkf->password_hash[i]);
		printf("\n");
	}

	if (property & PKF_PROP_ROOT) {
		printf("PKF TYPE = ROOT\n");
		return 1;
	} else {
		show_issuer(pkf);
	}
	
	return 0;
}

void pkfShow(PPKF pkf) {
	int root;
	char buffer[64];
	printf("PKF ID = ");
	show_xid(pkf->pkf_id);
	printf("EMAIL = %s\n", pkf->email);
	printf("ORGANIZATION = %s\n", pkf->organization);

	printf("BEGIN TIME = %s\n", ctime(&(pkf->begin_time)));
	printf("END TIME = %s\n", ctime(&(pkf->end_time)));

	printf("HASH ALGORITHM = %s\n", show_hash(pkf->sign_support.hash_id));
	printf("SIGN ALGORITHM = %s\n", show_sign(pkf->sign_support.sign_id));
	printf("PRNG ALGORITHM = %s\n", show_prng(pkf->sign_support.prng_id));
 
	show_property(pkf);
}

static int get_file_size(FILE* fp) {
	int total;
	
	fseek(fp, 0, SEEK_END);
	total = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	return total;
}

#define _fill_pkf_header(h)						\
	(h)->magic = PKF_MAGIC;						\
	   (h)->version = PKF_VERSION;				\
		  uuid_generate((h)->pkf_id);

#define DEF_PKF_PASSWORD            "aSBsb3ZlIHlvdSB4aWFvcWlhbiBmb3IgZXZlcgo="
PPKF pkfAlloc(int hash_id, int sign_id, int prng_id,
			  char* email, char* organ,
			  unsigned int end_time,
			  char* password, int crypt_id) {
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

	pkf->begin_time = time((time_t*)&(pkf->begin_time));
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
	free(pkf);
}

static int checksum_file(PPKF pkf) {
	int err;

	err = 0;

	return err;
}

/**
 * @brief 生成PKF证书
 * @param pkf 指向一个pkf证书指针
 * @param make_key 是否生成公私钥对
 * @param public_key_path 公钥路径
 * @param private_key_path 私钥路径
 * @paran nanan_path 我的爱狗
 */
#define TMP_PASSWORD_HASH_FILE      "./.password.hash.tmp"
#define TMP_PRIVATE_KEY_FILE        "./.private.key.tmp"
PPKF pkfMake(PPKF pkf, int make_key, 
			 char* public_key_path,
			 char* private_key_path,
			 char* nanan_path) {
	int err, t, size;
	char buffer[256];
	unsigned char* tmp;
	FILE* fp;
	char password[512];
	int crypt_id;

	t = 0;    /* 底下要用 */
	memset(buffer, 0, 256);

	crypt_id = pkf->crypt_id;
	strcpy(password, pkf->password);

	if (make_key) {
		/*
		 * 生成公私钥对
		 */
		//err = execl(nanan_path, "nanan", "-m", ".", NULL);
		sprintf(buffer, "%s --silent -m .", nanan_path);
		err = system(buffer);
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
			sprintf(buffer, 
					"%s --silent -1 %d -3 2 -4 0 -5 3 -e %s -o %s %s", 
					nanan_path,
					security.crypt_id,
					password,
					TMP_PRIVATE_KEY_FILE,
					private_key_path);
			system(buffer);

			fp = fopen(TMP_PRIVATE_KEY_FILE, "rb");
			if (!fp)
				goto _error;
			
			size = get_file_size(fp);
			err = fread(private_key, 1, size, fp);
			if (err != size)
				goto _error;

			/* 必须设置回NULL，打开PUBLIC KEY时要验证 */
			fclose(fp);fp = NULL;
			pkf->private_key_size = size;
			t += size;
			
			/* 删除临时文件 */
			sprintf(buffer, "rm -f %s", TMP_PRIVATE_KEY_FILE);
			system(buffer);

			/* 计算密码的SHA1值 */
			memset(buffer, 0, sizeof(buffer));
			sprintf(buffer, "echo %s | %s --silent -3 2 -h -o %s",
					password,
					nanan_path,
					TMP_PASSWORD_HASH_FILE);
			system(buffer);

			/* 读取HASH值 */
			{
				fp = fopen(TMP_PASSWORD_HASH_FILE, "rb");
				if (!fp) {
					goto _error;
				}
				err = fread(pkf->password_hash, 1, 16, fp);
				if (err != 16) {
					goto _error;
				}
				fclose(fp);
				/* 删除临时文件 */
				sprintf(buffer, "rm -f %s", TMP_PASSWORD_HASH_FILE);
				system(buffer);				  
			}
		}
	}

	/* 公钥不为空 */
	if (public_key_path || strlen(public_key_path)) {
		unsigned char* public_key;

		pkf->property |= PKF_PROP_PUBLIC;

		public_key = tmp + t;
		fp = fopen(public_key_path, "rb");
		if (!fp)
			goto _error;
			
		size = get_file_size(fp);
		pkf->public_key_size = size;
		err = fread(public_key, 1, size, fp);
		if (err != size)
			goto _error;

		t += size;
		fclose(fp);
	}

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

		if (checksum_file(pkf) != 0) {
			goto _error;
		}
	}

	return pkf;
 _error:
	if (tmp) free(tmp);
	if (pkf) free(pkf);
	if (fp) fclose(fp);
	return NULL;
}

#define TMP_SIGN_DATA_FILE     "./.sign_data.tmp"
#define TMP_SIGN_DATA_RESULT_FILE "./.sign_data_result.tmp"
#define TMP_OWNER_PRIVATE_FILE  "./.owner_private_key.tmp"
PPKF pkfSign(char* pkf_file, char* opk_file, 
			 char* nanan_path,
			 PPKF_ISSUER issuer) {
	PPKF pkf;
	char buffer[512];
	unsigned char* tmp;
	unsigned char* sign_data;
	FILE* fp;
	int err, size, sign_size;

	pkf = NULL;
	tmp = NULL;
	fp = NULL;

	tmp = (unsigned char*)malloc(10240);
	if (!tmp) {
		goto _error;
	}

	fp = fopen(pkf_file, "rb");
	if (!fp) {
		goto _error;
	}

	size = get_file_size(fp);
	err = fread(tmp, 1, size, fp);
	if (err != size) {
		goto _error;
	}
	fclose(fp);

	pkf = (PKF)tmp;

	/* 签名需要公钥存在 */
	if (pkf->property & PKF_PROP_PUBLIC == 0) {
		goto _error;
	}
	
	sign_data = (unsigned char*)&(pkf->file_size);
	sign_size = pkf->file_size - (unsigned int)(sign_data - tmp);
	
	if (sign_size <= 0) {
		goto _error;
	}

	fp = fopen(TMP_SIGN_DATA_FILE, "wb");
	if (!fp) {
		goto _error;
	}

	err = fwrite(sign_data, 1, sign_size, fp);
	if (err != sign_size) {
		goto _error;
	}
	fclose(fp);

	sprintf(buffer,
			"%s -2 %d -3 %d -4 %d -s --import-private-key %s -o %s %s",
			nanan_path,
			pkf->sign_support.sign_id,
			pkf->sign_support.sign_id,
			pkf->sign_support.sign_id,
			opk_file,
			TMP_SIGN_DATA_RESULT_FILE,
			TMP_SIGN_DATA_FILE);
	system(buffer);
	
	/* 删除临时文件 */
	sprintf(buffer, "rm -f %s", TMP_SIGN_DATA_FILE);
	system(buffer);

	fp = fopen(TMP_SIGN_DATA_RESULT_FILE, "rb");
	if (!fp) {
		goto _error;
	}

	size = get_file_size(fp);
	sign_data = tmp + pkf->file_size;
	err = fread(sign_data, 1, size, fp);
	if (err != size) {
		goto _error;
	}
	fclose(fp);

	sprintf(buffer, "rm -f %s", TMP_SIGN_DATA_RESULT_FILE);
	system(buffer);
	
	/* 设置颁发者签名信息 */
	issuer->sign_size = size;
	memcpy((unsigned char*)&(pkf->issuer),
		   issuer,
		   sizeof(PKF_ISSUER));

	

	/* 重新计算校验和 */
	if ((err = checksum_file(pkf))!= 0) {
		goto _error;
	}

	return pkf;
 _error:
	if (tmp) free(tmp);
	if (fp) fclose(fp);
	return NULL;
}

