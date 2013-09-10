#if !defined(__TOOLS_H__)
#define __TOOLS_H__

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#if 0
#if defined(HAVE_ENDIAN_H)
# include <endian.h>
#else /*not HAVE_ENDIAN_H*/
# define __BIG_ENDIAN 4321
# define __LITTLE_ENDIAN 1234
# if defined(HAVE_LITTLE_ENDIAN)
#  define __BYTE_ORDER __LITTLE_ENDIAN
# else
#  define __BYTE_ORDER __BIG_ENDIAN
# endif
#endif /*not HAVE_ENDIAN_H*/
#endif

#if !defined(NDEBUG) && defined(WITH_NANAN_ASSERT)
# undef assert
# define assert(x)														\
    ((x) ? ((void)0) : (ALOGE("ASSERT FAILED (%s:%d): %s",				\
							  __FILE__, __LINE__, #x), *(int*)39=39, (void)0) )
#endif

#if !defined(MIN)
#define MIN(x,y) (((x) < (y)) ? (x) : (y))
#endif

#if !defined(MAX)
#define MAX(x,y) (((x) > (y)) ? (x) : (y))
#endif

#define ALIGN_UP(x, n) (((size_t)(x) + (n) - 1) & ~((n) - 1))
#define ALIGN_DOWN(x, n) ((size_t)(x) & -(n))

#define NELEM(x) ((int) (sizeof(x) / sizeof((x)[0])))

#endif
