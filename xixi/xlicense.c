#include "xlicense.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <strings.h>

#include "common.h"
#include "tools.h"
#include "xlicense_tools.h"
#include "xlicense_show.h"

PXLICENSE xliceAlloc(int crypt_id) {
	PXLICENSE xlice;
	int err;

	xlice = (PXLICENSE)malloc(sizeof(XLICENSE));
	if (xlice) {
		memset(xlice, 0, sizeof(XLICENSE));
		xlice->magic = XLICE_MAGIC;
		xlice->version = XLICE_VERSION;
		xlice->file_size = sizeof(XLICENSE);

		//xlice->sign_id = sign_id;
		//xlice->hash_id = hash_id;
		xlice->crypt_id = crypt_id;
		//xlice->prng_id = prng_id;

		uuid_generate(xlice->id);
		xlice->property = XLICE_PROP_0;

		err = xlice_checksum_file(xlice);
		if (err != 0) {
			free(xlice);
			return NULL;
		}
		return xlice;
	}

	return NULL;
}

int xliceFree(PXLICENSE xlice) {
	if (xlice)
		free(xlice);
	return 0;
}

int xliceSetPKF0(PXLICENSE* xlice, 
				 PPKF pkf) {
	unsigned char* tmp;
	int size;

#if defined(CHECK_PKF_PRIVATE_KEY)
	/* 倒入的PKF不能含有私有密钥，保证一个PKF只能含有公钥 */
	if (pkf->property & PKF_PROP_PRIVATE) {
		return 2;
	}
#endif

	size = sizeof(XLICENSE) + pkf->file_size;
	tmp = (unsigned char*)malloc(size);
	if (!tmp)
		return 1;
	
	memcpy(tmp, *xlice, sizeof(XLICENSE));
	memcpy(tmp + sizeof(XLICENSE), 
		   (unsigned char*)pkf,
		   pkf->file_size);
	free(*xlice);
	*xlice = tmp;

	(*xlice)->pkf = (PPKF)(tmp + sizeof(XLICENSE));
	(*xlice)->file_size = size;

	return 0;
}

int xliceSetPKF(PXLICENSE* xlice, 
				char* pkf_path) {
	PPKF pkf;
	unsigned long pkf_size;
	int err;
	
	err = read_file(pkf_path,
					(unsigned char**)&pkf,
					&pkf_size);
	if (err != 0) {
		goto _error;
	}

	err = xliceSetPKF0(xlice,
					   pkf);
	if (err != 0) {
		goto _error;
	}
	
 _error:
	pkfFree(pkf);
	return err;
}

int xliceSetPKF1(PXLICENSE xlice) {
	unsigned int size;
	
	size = sizeof(XLICENSE) + sizeof(PKF);
	if (xlice->file_size < size) {
		return 1;
	}

	xlice->pkf = (PPKF)((unsigned char*)xlice + sizeof(XLICENSE));

	return 0;
}

#if defined(WITH_PROJECT_NAME)

int xliceSetProjectName(PXLICENSE xlice,
						char* project_name) {
	strcpy(xlice->project_name, project_name);
	return 0;
}

int xliceSetProjectName2(PXLICENSE xlice,
						 char* user_xlice_file) {
	int err;
	PXLICENSE user_xlice;
	unsigned long user_xlice_size;

	err = 0;

	err = read_file(user_xlice_file,
					(unsigned char**)&user_xlice,
					&user_xlice_size);
	if (err != 0) {
		goto _error;
	}

	strcpy(user_xlice->project_name,
		   xlice->project_name);

	err = write_file(user_xlice_file,
					 (unsigned char**)&user_xlice,
					 &user_xlice_size);
	if (err != 0) {
		goto _error;
	}

 _error:
	if (user_xlice) free(user_xlice);
	return err;
}

#endif

int xliceSignIt0(char* owner_private_key, 
				 char* user_xlice_file,
				 PXLICENSE* xlice) {
	int err;
	char tmpfile[256];
	unsigned char* tmp;
	unsigned char* value;
	unsigned char* sign_data;
	unsigned long sign_size;
	unsigned long value_size;

	err = 0;
	tmp = NULL;
	value = NULL;
	value_size = 0;

	srand(0);
	sprintf(tmpfile,
			".sign_xlice_data_%d", rand());

	sign_data = &((*xlice)->sign_start);
	sign_size = (*xlice)->file_size - 
		(unsigned int)(sign_data - (unsigned char*)(*xlice));

	err = write_file(tmpfile,
					 sign_data,
					 sign_size);
	if (err != 0) {
		goto _error;
	}

	err = sign_file(g_nanan_path,
					tmpfile,
					(*xlice)->pkf->sign_support.sign_id,
					(*xlice)->pkf->sign_support.hash_id,
					(*xlice)->pkf->sign_support.prng_id,
					owner_private_key,
					&value,
					&value_size);

	if (err != 0) {
		goto _error;
	}

	tmp = (unsigned char*)malloc((*xlice)->file_size + value_size);
	if (!tmp) goto _error;

	/* 写入签名 */
	memcpy(tmp,
		   (unsigned char*)(*xlice),
		   (*xlice)->file_size);

	memcpy(tmp + (*xlice)->file_size,
		   value,
		   value_size);

	xliceFree(*xlice);
	*xlice = tmp;
	tmp = NULL;

	(*xlice)->property &= ~XLICE_PROP_0;
	(*xlice)->property |= XLICE_PROP_AUTHED;

	(*xlice)->file_size += value_size;
	(*xlice)->sign_size = value_size;

	err = xlice_checksum_file((*xlice));
	if (err != 0) {
		goto _error;
	}

	err = write_file(user_xlice_file,
					 (unsigned char*)(*xlice),
					 (*xlice)->file_size);
	if (err != 0) {
		goto _error;
	}

 _error:
	delete_file(tmpfile);
	if (value) free(value);
	if (tmp) free(tmp);
	return err;
}

int xliceSignIt(char* owner_pkf_path,
				char* user_xlice_file,
				char* password) {
	PXLICENSE xlice;
	PPKF pkf;
	unsigned long xlice_size, pkf_size;
	int err;
	char owner_private_key[256];
	char new_file[256];

	err = 0;
	xlice = NULL;
	xlice_size = 0;

	srand(0);
	sprintf(owner_private_key,
			".owner_private_key_%d", rand());

	err = pkfReadPrivateKey(owner_pkf_path,
							owner_private_key,
							password);
	if (err != 0) {
		goto _error;
	}

	err = read_file(owner_pkf_path,
					(unsigned char**)&pkf,
					&pkf_size);
	if (err != 0) {
		goto _error;
	}

	/* 检查pkf的文件长度 */
	if (pkfCheckSize(pkf, pkf_size)) {
		goto _error;
	}

	err = read_file(user_xlice_file,
					(unsigned char**)&xlice,
					&xlice_size);
	if (err != 0) {
		goto _error;
	}

	/* 设置owner id */
	memcpy(&(xlice->owner_id),
		   &(pkf->pkf_id),
		   sizeof(uuid_t));

	/* 写入pkf文件到其后 */
	memcpy((unsigned char*)xlice + sizeof(XLICENSE),
		   (unsigned char*)pkf,
		   pkf_size);

	err = xliceSetPKF1(xlice);
	if (err != 0) {
		goto _error;
	}

	/* 更新一下xlice的文件长度 */
	xlice->file_size += pkf_size;

	sprintf(new_file, "%s.sign", user_xlice_file);
	err = xliceSignIt0(owner_private_key,
					   new_file,
					   &xlice);
	if (err != 0) {
		goto _error;
	}

	xlice_size = xlice->file_size;
	
 _error:
	if (pkf) pkfFree(pkf);
	if (xlice) xliceFree(xlice);
	delete_file(owner_private_key);
	return err;
}

void xliceShow(PXLICENSE xlice) {
	show_xlice(xlice);
}

int xliceVerify(char* owner_pkf_path,
				char* user_xlice_file,
				int* result) {
	int err;
	PXLICENSE xlice;
	unsigned char* sign_data;
	unsigned long xlice_size, sign_data_size;
	char public_key_file[256];
	char sign_file[256];
	unsigned char result_tmp;

	err = 0;
	xlice = NULL;
	xlice_size = 0;
	sign_data = NULL;
	sign_data_size = 0;
	result_tmp = 0;
	
	err = pkfReadPublicKey(owner_pkf_path, 
						   public_key_file);
	if (err != 0) {
		goto _error;
	}
	
	err = read_file(user_xlice_file,
					(unsigned char**)&xlice,
					&xlice_size);
	if (err != 0) {
		goto _error;
	}

	/* 获取签名 */
	sign_data = get_sign(xlice);
	if (sign_data == NULL) {
		goto _error;
	}
	sign_data_size = xlice->sign_size;

	sprintf(sign_file,
			".sign_file_%d", rand());
	err = write_file(sign_file,
					 sign_data,
					 sign_data_size);
	if (err != 0) {
		goto _error;
	}

	if (get_pkf(xlice) == NULL) {
		goto _error;
	}

	err = verify_file(g_nanan_path,
					  user_xlice_file,
					  xlice->pkf->sign_support.sign_id,
					  xlice->pkf->sign_support.hash_id,
					  xlice->pkf->sign_support.prng_id,
					  public_key_file,
					  sign_file,
					  &result_tmp);

	if (err != 0) {
		goto _error;
	}

	*result = result_tmp;

 _error:
	if (xlice) xliceFree(xlice);
	delete_file(public_key_file);
	delete_file(sign_file);
	return err;
}
