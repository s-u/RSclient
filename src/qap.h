#ifndef QAP_H__
#define QAP_H__


#include <Rinternals.h>
#include "rcompat.h"

#define RSERVE_PKG 1

#include "RSprotocol.h"

/* NOTE: we only support little-endian machines! */
#define NATIVE_COPY 1

/* stuff to enulate compatibility with Rserve's use */
#define DISABLE_ENCODING 1
#ifndef ptoi
#define ptoi(X) X
#endif
#ifndef itop
#define itop(X) ptoi(X)
#endif
#define fixdcpy(A, B) memcpy(A, B, 8)

/* does this R have R_xlen_t ? */
#ifdef R_XLEN_T_MAX
typedef R_xlen_t rlen_t;
/* we cannot use R_XLEN_T_MAX since that is 2^52 for 64-bit */
#ifdef LONG_VECTOR_SUPPORT
#define rlen_max ((rlen_t) 0xffffffffffffffff)
#else
#define rlen_max ((rlen_t) 0xffffffff)
#endif
#else
/* legacy compatibility to use unsigned long */
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
#endif /* R_XLEN_T_MAX */

SEXP QAP_decode(unsigned int **buf);
rlen_t QAP_getStorageSize(SEXP x);
unsigned int* QAP_storeSEXP(unsigned int* buf, SEXP x, rlen_t storage_size);

#endif
