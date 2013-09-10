#if ARGTYPE == 0

void nananArgChk(char *v, char *s, int d);
#define NANAN_ARGCHK(x) if (!(x)) { nananArgChk(#x, __FILE__, __LINE__); }
#define NANAN_ARGCHKVD(x) NANAN_ARGCHK(x)

#elif ARGTYPE == 1

#define NANAN_ARGCHK(x) assert((x))
#define NANAN_ARGCHKVD(x) NANAN_ARGCHK(x)

#elif ARGTYPE == 2

#define NANAN_ARGCHK(x) if (!(x)) { fprintf(stderr, "\nwarning: ARGCHK failed at %s:%d\n", __FILE__, __LINE__); }
#define NANAN_ARGCHKVD(x) NANAN_ARGCHK(x)

#elif ARGTYPE == 3

#define NANAN_ARGCHK(x) 
#define NANAN_ARGCHKVD(x) NANAN_ARGCHK(x)

#elif ARGTYPE == 4

#define NANAN_ARGCHK(x)   if (!(x)) return CRYPT_INVALID_ARG;
#define NANAN_ARGCHKVD(x) if (!(x)) return;

#endif
