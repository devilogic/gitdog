static void show_sign(PXLICENSE xlice) {
	unsigned char* sign;
	unsigned long sign_size;

	sign = get_sign(xlice);
	if (sign) {
		sign_size = xlice->sign_size;
		show_key(sign, sign_size);
	}
}

static void show_xlice(PXLICENSE xlice) {

	printf("ID = ");
	show_xid(xlice->id);

	if (xlice->property & XLICE_PROP_0 == 0) {
		/* OWNER */
		printf("OWNER ID = ");
		show_xid(xlice->owner_id);
	}

	printf("CRYPT ALGORITHM = %s\n", 
		   show_crypt_algorithm(xlice->crypt_id));
	printf("SIGN ALGORITHM = %s\n", 
		   show_sign_algorithm(xlice->sign_id));
	printf("HASH ALGORITHM = %s\n", 
		   show_hash_algorithm(xlice->hash_id));
	printf("PRNG ALGORITHM = %s\n", 
		   show_prng_algorithm(xlice->prng_id));

	printf("XCHANGE COUNT = %d\n", xlice->xchange_count);
	printf("SIGN SIZE = %d\n", xlice->sign_size);
	show_sign(xlice);
}
