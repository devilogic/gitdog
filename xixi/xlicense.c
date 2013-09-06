#include "xlicense.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#include <uuid/uuid.h>

#include "common.h"
#include "tools.h"
#include "xlicense_tools.h"
#include "xlicense_show.h"

PXLICENSE xliceAlloc(int crypt_id,
					 int sign_id,
					 int hash_id,
					 int prng_id) {
	PXLICENSE xlice;
	int err;

	xlice = (PXLICENSE)malloc(sizeof(XLICENSE));
	if (xlice) {
		memset(xlice, 0, sizeof(XLICENSE));
		xlice->magic = XLICE_MAGIC;
		xlice->version = XLICE_VERSION;
		xlice->file_size = sizeof(XLICENSE);

		xlice->sign_id = sign_id;
		xlice->hash_id = hash_id;
		xlice->crypt_id = crypt_id;
		xlice->prng_id = prng_id;

		uuid_generate(xlice->id);
		xlice->property = XLICE_PROP_0;

		err = checksum_file(xlice);
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
				 PXLICENSE xlice) {
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

	sign_data = &(xlice->sign_start);
	sign_size = xlice->file_size - (unsigned int)(sign_data - (unsigned char*)xlice);

	err = write_file(tmpfile,
					 sign_data,
					 sign_size);
	if (err != 0) {
		goto _error;
	}

	err = sign_file(g_nanan_path,
					tmpfile,
					xlice->sign_id,
					xlice->hash_id,
					xlice->prng_id,
					owner_private_key,
					&value,
					&value_size);

	if (err != 0) {
		goto _error;
	}

	tmp = (unsigned char*)malloc(xlice->file_size + value_size);
	if (!tmp) goto _error;

	memcpy(tmp,
		   (unsigned char*)xlice,
		   xlice->file_size);

	memcpy(tmp + xlice->file_size,
		   value,
		   value_size);

	free(xlice);
	xlice = tmp;
	tmp = NULL;

	xlice->property &= ~XLICE_PROP_0;
	xlice->property |= XLICE_PROP_AUTHED;

	xlice->file_size += value_size;
	xlice->sign_size = value_size;

	err = xlice_checksum_file(xlice);
	if (err != 0) {
		goto _error;
	}

	err = write_file(user_xlice_file,
					 (unsigned char*)xlice,
					 xlice->file_size);
	if (err != 0) {
		goto _error;
	}

	return 0;
 _error:
	delete_file(tmpfile);
	if (value) free(value);
	if (tmp) free(tmp);
	if (xlice) free(xlice);
	return err;
}

int xliceSignIt(char* owner_pkf,
				char* user_xlice_file,
				char* password) {
	PXLICENSE xlice;
	unsigned long xlice_size;
	int err;
	char owner_private_key[256];

	err = 0;
	xlice = NULL;
	xlice_size = 0;

	srand(0);
	sprintf(owner_private_key,
			".sign_xlice_opk_%d", rand());

	err = pkfReadPrivateKey(owner_pkf,
							owner_private_key,
							password);
	if (err != 0) {
		goto _error;
	}

	err = read_file(user_xlice_file,
					(unsigned char**)&xlice,
					&xlice_size);
	if (err != 0) {
		goto _error;
	}
	
	err = xliceSignIt(owner_private_key,
					  xlice);
	if (err != 0) {
		goto _error;
	}
	
 _error:
	if (pkf) pkfFree(pkf);
	if (xlice) xliceFree(xlice);
	delete_file(owner_private_key);
	return err;
}

void xliceShow(PXLICENSE xlice) {
	show_xlice(xlice);
}

int xliceSetOwnerID(PXLICENSE xlice,
					char* owner_id) {
	XID id;

	

	return 0;
}
