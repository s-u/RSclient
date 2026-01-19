/* R compatibilty macros - working around re-mapped API points */
#ifndef RCOMPAT_H__
#define RCOMPAT_H__

#include <Rversion.h>

#if (R_VERSION >= R_Version(2,0,0))
/* EXTPTR */
#ifdef  EXTPTR_PTR
#undef  EXTPTR_PTR
#endif
#define EXTPTR_PTR(X) R_ExternalPtrAddr(X)
#ifdef  EXTPTR_PROT
#undef  EXTPTR_PROT
#endif
#define EXTPTR_PROT(X) R_ExternalPtrProtected(X)
#ifdef  EXTPTR_TAG
#undef  EXTPTR_TAG
#endif
#define EXTPTR_TAG(X) R_ExternalPtrTag(X)
/* CLOSXP */
#ifdef  BODY_EXPR
#undef  BODY_EXPR
#endif
#define BODY_EXPR(X) R_ClosureExpr(X)
#endif

#if (R_VERSION >= R_Version(4,5,0))
/* CLOSXP - new API in 4.5.0 */
#ifdef BODY
#undef BODY
#endif
#define BODY(X) R_ClosureBody(X)
#ifdef FORMALS
#undef FORMALS
#endif
#define FORMALS(X) R_ClosureFormals(X)
#ifdef CLOENV
#undef CLOENV
#endif
#define CLOENV(X) R_ClosureEnv(X)
#endif /* R 4.5.0 */

#if (R_VERSION >= R_Version(4,6,0))
/* we have a probelm - our serialization relies on the values of ATTRIB.
   we cannot use the official API, because it is impossible to copy
   attributes from something that is not already an object with attributes
   and it's impossible to restore them indiviudally since some attributes
   rely on the values of the others (e.g. class, dim, names). So we have no
   choice but to grab ATTRIB ourselves. This is the same as what was used
   in R <4.6.0, but we have to make sure we revisit this if the
   representation changes. If it does, we are in trouble since the
   serialization relies on exactly this representation so it would be hard
   to adapt. So perhaps we should think about re-thinking how we store
   attributes and divide them by semantic meaning or similar ... */
#include <stdint.h>
#ifdef SET_ATTRIB
#undef SET_ATTRIB
#endif
#ifdef ATTRIB
#undef ATTRIB
#endif
typedef struct sexp_compat { uint64_t bits; void *attr; } sexp_compat_attr;
#define ATTRIB(X) ((SEXP)(((sexp_compat_attr*)(X))->attr))
/* both X and A are expected to be protected; we create a temporary object
   on which we call SHALLOW_DUPLICATE_ATTRIB() with the injected attrs to
   make sure the memory mgmt is all ok. */
#define SET_ATTRIB(X, A) do { SEXP tmp_ = PROTECT(CONS(R_NilValue, R_NilValue)); sexp_compat_attr *t = (sexp_compat_attr*) tmp_; t->attr = (void*)(A); SHALLOW_DUPLICATE_ATTRIB(X, tmp_); t->attr = (void*)R_NilValue; UNPROTECT(1); } while(0)
#else /* R <4.6.0 */
#define R_allocResizableVector(X, L) Rf_allocVector(X, L)
#define R_resizeVector(X, L) SETLENGTH(X, L)
#endif /* R <4.6.0 */
#endif /* RCOMPAT_H__ */
