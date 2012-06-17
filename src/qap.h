#ifndef QAP_DECODE_H__
#define QAP_DECODE_H__

#ifndef USE_RINTERNALS
#define USE_RINTERNALS 1
#include <Rinternals.h>
#endif

#include "RSprotocol.h"

/* stuff to enulate compatibility with Rserve's use */
#define DISABLE_ENCODING 1
#define ptoi(X) X
#define itop(X) ptoi(X)
#define fixdcpy(A, B) memcpy(A, B, 8)
typedef unsigned long rlen_t;

#ifdef ULONG_MAX
#define rlen_max ULONG_MAX
#else
#ifdef __LP64__
#define rlen_max 0xffffffffffffffffL 
#else
#define rlen_max 0xffffffffL
#endif /* __LP64__ */
#endif /* ULONG_MAX */

SEXP QAP_decode(unsigned int **buf, int *UPC);
rlen_t QAP_getStorageSize(SEXP x);
unsigned int* QAP_storeSEXP(unsigned int* buf, SEXP x, rlen_t storage_size);

#endif
