/*
   (C)Copyright 2012-2019 Simon Urbanek.

   Released under GPL v2, no warranties.

*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <sys/types.h>
#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#define USE_TLS 1
static int wsock_up = 0;
#define MAX_RECV 65536
#else
#define MAX_RECV (512*1025)
#define closesocket(C) close(C)
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif
/* until we use confgiure we hard-code TLS use for now */
#define USE_TLS 1
/* and we enable IPv6 if we see it */
#ifdef AF_INET6
#define USE_IPV6 1
#endif
#endif
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>

#ifdef USE_THREADS
#include "sbthread.h"
#endif

#ifdef USE_TLS

/* OpenSSL 3.x requires this */
#ifndef OPENSSL_SUPPRESS_DEPRECATED
#define OPENSSL_SUPPRESS_DEPRECATED 1
#endif

#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#endif

#define USE_RINTERNALS
#include <Rinternals.h>

/* asynchronous connection status */
#define ACS_CONNECTING    1
#define ACS_CONNECTED     2 

#define ACS_IOERR        -1
#define ACS_HSERR        -2  /* handshake error */

typedef struct rsconn {
    int s, intr, in_cmd, thread, port;
    void *tls;
    unsigned int send_len, send_alloc;
    char *send_buf, *host;
    FILE *stream;
    const char *last_error;
    SEXP oob_send_cb, oob_msg_cb;
    int (*send)(struct rsconn *, const void *, int);
    int (*recv)(struct rsconn *, void *, int);
} rsconn_t;

#define rsc_ok(X) (((X)->s) != -1)

#define IOerr(C, X) { C->last_error = X; if ((C)->thread) { (C)->thread = ACS_IOERR; return -1; } else Rf_error(X); }

static int sock_send(rsconn_t *c, const void *buf, int len) {
    if (c->s == -1)
	IOerr(c, "connection is already closed");
    if (c->intr) {
	closesocket(c->s);
	c->s = -1;
	IOerr(c, "previous operation was interrupted, connection aborted");
    }
    return send(c->s, buf, len, 0);
}

#if defined EAGAIN && ! defined EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif
#if ! defined EAGAIN && defined EWOULDBLOCK
#define EAGAIN EWOULDBLOCK 
#endif

static int sock_recv(rsconn_t *c, void *buf, int len) {
    char* cb = (char*) buf;
    if (c->intr && c->s != -1) {
	closesocket(c->s);
	c->s = -1;
	IOerr(c, "previous operation was interrupted, connection aborted");
    }
    while (len > 0) {
	int n = recv(c->s, cb, len, 0);
	/* fprintf(stderr, "sock_recv(%d) = %d [errno=%d]\n", len, n, errno); */
	/* bail out only on non-timeout errors */
	if (n == -1 && errno != EAGAIN && errno != EWOULDBLOCK)
	    return -1;
	if (n == 0)
	    break;
	if (n > 0) {
	    cb += n;
	    len -= n;
	}
	if (len) {
	    c->intr = 1;
	    R_CheckUserInterrupt();
	    c->intr = 0;
	}
    }
    return (int) (cb - (char*)buf);
}

#ifdef USE_TLS
static int rsc_abort(rsconn_t *c, const char *reason);

static int tls_send(rsconn_t *c, const void *buf, int len) {
    if (c->intr)
	rsc_abort(c, "previous operation was interrupted, connection aborted");

    /* SSL can fail with SSL_ERROR_WANT_READ/WRITE which is retriable */
    while (1) {
        int n = SSL_write((SSL*)c->tls, buf, len);
        if (n <= 0) {
            int serr = SSL_get_error((SSL*)c->tls, n);
            if (serr != SSL_ERROR_WANT_READ && serr != SSL_ERROR_WANT_WRITE)
                return n;
            /* means we should allow interrupt as it can retry indefinitely */
            c->intr = 1;
            R_CheckUserInterrupt();
            c->intr = 0;
	} else return n;
    }
    return -1; /* unreachable */
}

static int tls_recv(rsconn_t *c, void *buf, int len) {
    if (c->intr)
	rsc_abort(c, "previous operation was interrupted, connection aborted");

    /* SSL can fail with SSL_ERROR_WANT_READ/WRITE which is retriable */
    while (1) {
	int n = SSL_read((SSL*)c->tls, buf, len);
	if (n <= 0) {
	    int serr = SSL_get_error((SSL*)c->tls, n);
	    if (serr != SSL_ERROR_WANT_READ && serr != SSL_ERROR_WANT_WRITE)
		return n;
	    /* means we should allow interrupt as it can retry indefinitely */
	    c->intr = 1;
	    R_CheckUserInterrupt();
	    c->intr = 0;
	} else return n;
    }
    return -1; /* unreachable */
}

static int first_tls = 1;

#include <openssl/err.h>

static void init_tls() {
    if (first_tls) {
	SSL_library_init();	
	SSL_load_error_strings();
	first_tls = 0;
    }
}

static int tls_upgrade(rsconn_t *c, int verify, const char *chain, const char *key, const char *ca) {
    SSL *ssl;
    SSL_CTX *ctx;
    if (first_tls)
	init_tls();
    ctx = SSL_CTX_new(SSLv23_client_method());
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    if (chain && SSL_CTX_use_certificate_chain_file(ctx, chain) != 1) {
	Rf_warning("Cannot load certificate chain from file %s", chain);
	return -1;
    }
    if (key && SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
	Rf_warning("Cannot load certificate key from file %s", key);
	return -1;
    }
    if (ca && SSL_CTX_load_verify_locations(ctx, ca, 0) != 1) {
	Rf_warning("Cannot load CA certificates from file %s", chain);
	return -1;
    }
    SSL_CTX_set_verify(ctx, (verify == 0) ? SSL_VERIFY_NONE : SSL_VERIFY_PEER, 0);
    c->tls = ssl = SSL_new(ctx);
    c->send = tls_send;
    c->recv = tls_recv;
    SSL_set_fd(ssl, c->s);
    /* SSL_CTX_free(ctx) // check whether this is safe - it should be since ssl has the reference ... */
    return SSL_connect(ssl);
}
#endif

/* we split alloc and connect so alloc can be done on the main thread
   and connect on a separate one */
static rsconn_t *rsc_alloc() {
    rsconn_t *c = (rsconn_t*) calloc(sizeof(rsconn_t), 1);
#ifdef WIN32
    if (!wsock_up) {
	 WSADATA dt;
	 /* initialize WinSock 2.0 (WSAStringToAddress is 2.0 feature) */
	 WSAStartup(MAKEWORD(2,0), &dt);
	 wsock_up = 1;
    }
#endif
    c->intr = 0;
    c->thread = 0;
    c->s = -1;
    c->send_alloc = 65536;
    c->send_len = 0;
    c->send_buf = (char*) malloc(c->send_alloc);
    c->tls = 0;
    c->in_cmd = 0;
    c->oob_send_cb = R_NilValue;
    c->oob_msg_cb = R_NilValue;
    c->send = sock_send;
    c->recv = sock_recv;
    if (!c->send_buf) { free(c); return 0; }
    return c;
}

static rsconn_t *rsc_connect_ex(const char *host, int port, rsconn_t *c) {
    int family, connected = 0;
#ifdef WIN32
    family = AF_INET;
#else
    family = port ? AF_INET : AF_LOCAL;
#endif
#ifdef USE_IPV6
    /* we use getaddrinfo to have the system figure the family and address for us */
    /* FIXME: is there any reason we don't use that in general? Do all systems support this? */
    if (host && family == AF_INET) {
	struct addrinfo hints, *ail = 0, *ai;
	char port_s[8];
	snprintf(port_s, sizeof(port_s), "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, port_s, &hints, &ail) == 0) {
	    for (ai = ail; ai; ai = ai->ai_next)
		if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6) {
		    c->s = socket(ai->ai_family, SOCK_STREAM, ai->ai_protocol);
		    if (c->s != -1) {
			if (connect(c->s, ai->ai_addr, ai->ai_addrlen) == 0)
			    break;
			/* didn't work - try another address (if ther are any) */
			closesocket(c->s);
			c->s = -1;
		    }
		}
	    if (ail)
		freeaddrinfo(ail);
	}
	if (c->s != -1) /* the socket will be valid only if connect() succeeded */
	    connected = 1;
    } else
#endif
	c->s = socket(family, SOCK_STREAM, 0);
#ifdef SO_RCVTIMEO
    { /* set receive timeout so we can interrupt read operations */
	struct timeval tv;
	tv.tv_sec  = 0;
	tv.tv_usec = 200000; /* 200ms */
	setsockopt(c->s, SOL_SOCKET, SO_RCVTIMEO, (const char *) &tv, sizeof(tv));
    }
#endif
    if (c->s != -1 && !connected) {
	if (family == AF_INET) {
	    struct sockaddr_in sin;
	    struct hostent *haddr;
	    sin.sin_family = AF_INET;
	    sin.sin_port = htons(port);
	    if (host) {
#ifdef WIN32
		int al = sizeof(sin);
		if (WSAStringToAddress((LPSTR)host, sin.sin_family, 0, (struct sockaddr*)&sin, &al) != 0) {
		    if (!(haddr = gethostbyname(host))) { /* DNS failed, */
			closesocket(c->s);
			c->s = -1;
		    }
		    sin.sin_addr.s_addr = *((uint32_t*) haddr->h_addr); /* pick first address */
	    }
		/* for some reason Windows trashes the structure so we need to fill it again */
		sin.sin_family = AF_INET;
		sin.sin_port = htons(port);
#else
		if (inet_pton(sin.sin_family, host, &sin.sin_addr) != 1) { /* invalid, try DNS */
		    if (!(haddr = gethostbyname(host))) { /* DNS failed, */
			closesocket(c->s);
			c->s = -1;
		    }
		    sin.sin_addr.s_addr = *((uint32_t*) haddr->h_addr); /* pick first address */
		}
#endif
	    } else
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	    if (c->s != -1 && connect(c->s, (struct sockaddr*)&sin, sizeof(sin))) {
		closesocket(c->s);
		c->s = -1;
	    }
	} else {
#ifndef WIN32
	    struct sockaddr_un sau;
	    memset(&sau, 0, sizeof(sau));
	    sau.sun_family = AF_LOCAL;
	    if (strlen(host) + 1 > sizeof(sau.sun_path)) {
		closesocket(c->s);
		c->s = -1;
	    } else
		strcpy(sau.sun_path, host);
	    if (c->s != -1 && connect(c->s, (struct sockaddr*)&sau, sizeof(sau))) {
		closesocket(c->s);
		c->s = -1;
	    }
#else /* this should never happen */
	    c->s = -1; 
#endif
	}
    }
    if (c->s == -1) {
	free(c->send_buf);
	free(c);
	return 0;
    }
    return c;
}

static rsconn_t *rsc_connect(const char *host, int port) {
    rsconn_t *c = rsc_alloc();
    if (!c) return c;
    return rsc_connect_ex(host, port, c);
}

static int rsc_abort(rsconn_t *c, const char *reason) {
#if USE_TLS
    if (!c->thread) {
	long tc = ERR_get_error();
	if (tc) {
	    char *te = ERR_error_string(tc, 0);
	    if (te) REprintf("TLS error: %s\n", te);
	}
    }
#endif
    if (c->s != -1)
	closesocket(c->s);
    c->s = -1;
    c->in_cmd = 0;
    c->last_error = reason;
    if (!c->thread)
	REprintf("rsc_abort: %s\n", reason);
    return -1;
}

static int rsc_flush(rsconn_t *c) {
    if (c->s == -1)
	IOerr(c, "connection lost");
    if (c->s != -1 && c->send_len) {
	int n, sp = 0;
#if RC_DEBUG
	int i;
	fprintf(stderr, "INFO.send:");
	for (i = 0; i < c->send_len; i++) fprintf(stderr, " %02x", (int) ((uint8_t*)c->send_buf)[i]);
	fprintf(stderr, "  ");
	for (i = 0; i < c->send_len; i++) fprintf(stderr, "%c", (((uint8_t*)c->send_buf)[i] > 31 && ((uint8_t*)c->send_buf)[i] < 128) ? ((uint8_t*)c->send_buf)[i] : '.');
	fprintf(stderr, "\n");
#endif
	while (sp < c->send_len &&
	       (n = c->send(c, c->send_buf + sp, c->send_len - sp)) > 0)
	    sp += n;
	if (sp < c->send_len)
	    rsc_abort(c, "send error");
    }
    c->send_len = 0;
    return 0;
}

static void rsc_close(rsconn_t *c) {
    if (!c) return;
    if (c->s != -1)
	rsc_flush(c);
#ifdef USE_TLS
    if (c->tls) {
	if (SSL_shutdown((SSL*)c->tls) == 0)
	    SSL_shutdown((SSL*)c->tls);
	SSL_free((SSL*)c->tls);
	c->tls = 0;
    }
#endif
    if (c->s != -1)
	closesocket(c->s);
    if (c->host)
	free(c->host);
    free(c->send_buf);
    free(c);
}

static long rsc_write(rsconn_t *c, const void *buf, long len) {
    const char *cb = (const char*) buf;
    while (c->send_len + len > c->send_alloc) {
	int ts = c->send_alloc - c->send_len;
	if (ts) {
	    memcpy(c->send_buf + c->send_len, cb, ts);
	    c->send_len += ts;
	    cb += ts;
	    len -= ts;
	}
	rsc_flush(c);
    }
    memcpy(c->send_buf + c->send_len, cb, len);
    c->send_len += len;
    return (c->s == -1) ? -1 : len;
}

static long rsc_read(rsconn_t *c, void *buf, long needed) {
    char *ptr = (char*) buf;
    if (needed < 0) return rsc_abort(c, "attempt to read negative number of bytes (integer overflow?)");
    if (c->s == -1) return -1;
    while (needed > 0) {
	int n = c->recv(c, ptr, (needed > MAX_RECV) ? MAX_RECV : needed);
	if (n < 0) return rsc_abort(c, "read error");
	if (n == 0) return rsc_abort(c, "connection closed by peer");
#if RC_DEBUG
	int i;
	fprintf(stderr, "INFO.recv:");
	for (i = 0; i < n; i++) fprintf(stderr, " %02x", (int) ((unsigned char*)ptr)[i]);
	fprintf(stderr, "  ");
	for (i = 0; i < n; i++) fprintf(stderr, "%c", (((unsigned char*)ptr)[i] > 31 && ((unsigned char*)ptr)[i] < 128) ? ((unsigned char*)ptr)[i] : '.');
	fprintf(stderr, "\n");
#endif
	ptr += n;
	needed -= n;
    }
    return (long) (ptr - (char*) buf);
}

/* Note: OC handshake also uses the slurp buffer as scratch */
static char slurp_buffer[65536];

static long rsc_slurp(rsconn_t *c, long needed) {
    long len = needed;
    while (needed > 0) {
	int n = c->recv(c, slurp_buffer, (needed > sizeof(slurp_buffer)) ? sizeof(slurp_buffer) : needed);
	if (n < 0) return rsc_abort(c, "read error");
	if (n == 0) return rsc_abort(c, "connection closed by peer");
	needed -= n;
    }
    return len;
}

/* Rserve protocol */
#include "RSprotocol.h"
#include "qap.h"

/* --- R API -- */

#define R2UTF8(X) translateCharUTF8(STRING_ELT(X, 0))

static void rsconn_fin(SEXP what) {
    rsconn_t *c = (rsconn_t*) EXTPTR_PTR(what);
    if (c) rsc_close(c);
}

static void setAttrib_(SEXP x, const char *sym, SEXP sVal) {
    PROTECT(sVal);
    Rf_setAttrib(x, Rf_install(sym), sVal);
    UNPROTECT(1);
}

SEXP RS_connect(SEXP sHost, SEXP sPort, SEXP useTLS, SEXP sProxyTarget, SEXP sProxyWait, SEXP sVerify,
		SEXP sChainFile, SEXP sKeyFile, SEXP sCAFile) {
    int port = asInteger(sPort), use_tls = (asInteger(useTLS) == 1), px_get_slot = (asInteger(sProxyWait) == 0), n;
    const char *host;
    char idstr[32];
    rsconn_t *c;
    SEXP res, caps = R_NilValue;

    if (port < 0 || port > 65534)
	Rf_error("Invalid port number");
#ifdef WIN32
    if (!port)
	Rf_error("unix sockets are not supported in Windows");
#endif
#ifndef USE_TLS
    if (use_tls)
	Rf_error("TLS is not supported in this build - recompile with OpenSSL");
#endif
    if (sHost == R_NilValue && !port)
	Rf_error("socket name must be specified in socket mode");
    if (sHost == R_NilValue)
	host = "127.0.0.1";
    else {
	if (TYPEOF(sHost) != STRSXP || LENGTH(sHost) != 1)
	    Rf_error("host must be a character vector of length one");
	host = R2UTF8(sHost);
    }
    c = rsc_connect(host, port);
    if (!c)
	Rf_error("cannot connect to %s:%d", host, port);
#ifdef USE_TLS
    if (use_tls) {
	const char *chain = ((TYPEOF(sChainFile) == STRSXP) && LENGTH(sChainFile) > 0) ? CHAR(STRING_ELT(sChainFile, 0)) : 0;
	const char *key = ((TYPEOF(sKeyFile) == STRSXP) && LENGTH(sKeyFile) > 0) ? CHAR(STRING_ELT(sKeyFile, 0)) : 0;
	const char *ca = ((TYPEOF(sCAFile) == STRSXP) && LENGTH(sCAFile) > 0) ? CHAR(STRING_ELT(sCAFile, 0)) : 0;
	if ((n = tls_upgrade(c, asInteger(sVerify), chain, key, ca)) != 1) {
	    int serr = SSL_get_error((SSL*)c->tls, n);
	    unsigned long err = ERR_get_error();
	    const char *es = ERR_error_string(err, 0);
	    rsc_close(c);
	    Rf_error("TLS handshake failed (SSL_error=%d; %s)", serr, es);
	}
    }
#endif	
    if (rsc_read(c, idstr, 32) != 32) {
	rsc_close(c);
	Rf_error("Handshake failed - ID string not received");
    }
    if (!memcmp(idstr, "RSpx", 4) && !memcmp(idstr + 8, "QAP1", 4)) { /* RSpx proxy protocol */
	const char *proxy_target;
	struct phdr hdr;
	if (TYPEOF(sProxyTarget) != STRSXP || LENGTH(sProxyTarget) < 1) {
	    rsc_close(c);
	    Rf_error("Connected to a non-transparent proxy, but no proxy target was specified");
	}
	/* send CMD_PROXY_TARGET and re-fetch ID string */
	proxy_target = CHAR(STRING_ELT(sProxyTarget, 0));
	hdr.cmd = itop(CMD_PROXY_TARGET);
	hdr.len = itop(strlen(proxy_target) + 1);
	hdr.dof = 0;
	hdr.res = 0;
	rsc_write(c, &hdr, sizeof(hdr));
	rsc_write(c, proxy_target, strlen(proxy_target) + 1);
	if (px_get_slot) { /* send CMD_PROXY_GET_SLOT as well if requested */
	    hdr.cmd = itop(CMD_PROXY_GET_SLOT);
	    hdr.len = 0;
	    rsc_write(c, &hdr, sizeof(hdr));
	}
	rsc_flush(c);
	if (rsc_read(c, idstr, 32) != 32) {
	    rsc_close(c);
	    Rf_error("Handshake failed - ID string not received (after CMD_PROXY_TARGET)");
	}
    }
    /* OC mode */
    if (((const int*)idstr)[0] == itop(CMD_OCinit)) {
	int sb_len;
	struct phdr *hdr = (struct phdr *) idstr;
	hdr->len = itop(hdr->len);
	if (hdr->res || hdr->dof || hdr->len > sizeof(slurp_buffer) || hdr->len < 16) {
	    rsc_close(c);
	    Rf_error("Handshake failed - invalid RsOC OCinit message");
	}
	sb_len = 32 - sizeof(struct phdr);
	memcpy(slurp_buffer, idstr + sizeof(struct phdr), sb_len);
	if (rsc_read(c, slurp_buffer + sb_len, hdr->len - sb_len) != hdr->len - sb_len) {
	    rsc_close(c);
	    Rf_error("Handshake failed - truncated RsOC OCinit message");
	} else {
	    unsigned int *ibuf = (unsigned int*) slurp_buffer;
	    int par_type = PAR_TYPE(*ibuf);
	    int is_large = (par_type & DT_LARGE) ? 1 : 0;
	    if (is_large) par_type ^= DT_LARGE;
	    if (par_type != DT_SEXP) {
		rsc_close(c);
		Rf_error("Handshake failed - invalid payload in OCinit message");
	    }
	    ibuf += is_large + 1;
	    caps = QAP_decode(&ibuf);
	    if (caps != R_NilValue)
		PROTECT(caps);
	}
    } else {
	if (memcmp(idstr, "Rsrv", 4) || memcmp(idstr + 8, "QAP1", 4)) {
	    rsc_close(c);
	    Rf_error("Handshake failed - unknown protocol");
	}

	/* supported range 0100 .. 0103 */
	if (memcmp(idstr + 4, "0100", 4) < 0 || memcmp(idstr + 4, "0103", 4) > 0) {
	    rsc_close(c);
	    Rf_error("Handshake failed - server protocol version too high");
	}
    }

    res = PROTECT(R_MakeExternalPtr(c, R_NilValue, R_NilValue));
    setAttrib(res, R_ClassSymbol, mkString("RserveConnection"));
    R_RegisterCFinalizer(res, rsconn_fin);
    if (caps != R_NilValue) {
	setAttrib_(res, "capabilities", caps);
	UNPROTECT(1);
    }	  
    UNPROTECT(1);
    return res;
}

SEXP RS_close(SEXP sc) {
    rsconn_t *c;
    if (!inherits(sc, "RserveConnection")) Rf_error("invalid connection");
    c = (rsconn_t*) EXTPTR_PTR(sc);
    if (!c) return R_NilValue;
    /* we can't use rsc_close because it frees the connection object */
    closesocket(c->s);
    c->s = -1;
    c->in_cmd = 0;
    return R_NilValue;
}

static const char *rs_status_string(int status) {
    switch (status) {
    case 0: return "(status is OK)";
    case 127:
    case 1: return "error in R during evaluation";
    case 2: return "R parser: input incomplete";
    case 3: return "R parser: error in the expression";
    case 4: return "R parser: EOF reached";
    case ERR_auth_failed: return "authentication failed";
    case ERR_conn_broken: return "connection is broken";
    case ERR_inv_cmd: return "invalid command";
    case ERR_inv_par: return "invalid command parameter";
    case ERR_Rerror: return "fatal R-side error";
    case ERR_IOerror: return "I/O error on the server";
    case ERR_notOpen: return "I/O operation on a closed file";
    case ERR_accessDenied: return "access denied";
    case ERR_unsupportedCmd: return "unsupported command";
    case ERR_unknownCmd: return "unknown command";
    case ERR_data_overflow: return "data overflow";
    case ERR_object_too_big: return "object is too big";
    case ERR_out_of_mem: return "out of memory";
    case ERR_ctrl_closed: return "no control line present (control commands disabled or server shutdown)";
    case ERR_session_busy: return "session is busy";
    case ERR_detach_failed: return "unable to detach session";
    case ERR_disabled: return "feature is disabled";
    case ERR_unavailable: return "feature is not available in this build of the server";
    case ERR_cryptError: return "crypto-system error";
    case ERR_securityClose: return "connection closed due to security violation";
    }
    return "(unknown error code)";
}

#ifdef USE_THREADS

/* threaded version - can be run ona separate threads, does not use
   any R API and responds with ERR_unsupportedCmd to OOB commands */
static long get_hdr_mt(rsconn_t *c, struct phdr *hdr) {
    long tl = 0;
    while (1) {
	if (rsc_read(c, hdr, sizeof(*hdr)) != sizeof(*hdr)) {
	    c->in_cmd = 0;
	    closesocket(c->s);
	    c->s = -1;
	    IOerr(c, "read error - could not obtain response header");
	}
#if LONG_MAX > 2147483647
	tl = hdr->res;
	tl <<= 32;
	tl |= hdr->len;
#else
	tl = hdr->len;
#endif
	/* OOB is not supported in MT mode */
	if (hdr->cmd & CMD_OOB) {
	    struct phdr rhdr;
	    int err = 0;
	    memset(&rhdr, 0, sizeof(rhdr));

	    /* FIXME: Rserve has a bug(?) that sets CMD_RESP on OOB commands so we clear it for now ... */
	    hdr->cmd &= ~CMD_RESP;

	    if (IS_OOB_STREAM_READ(hdr->cmd)) { /* the only request we allow is stream read */
		if (!c->stream || OOB_USR_CODE(hdr->cmd)) { /* we support only one stream - if present */
		    rsc_slurp(c, tl);
		    err = ERR_notOpen;
		} else if (tl > 16) {
		    rsc_slurp(c, tl);
		    err = ERR_inv_par;
		} else {
		    /* the request size is limited by the send buffer */
		    unsigned int req_off = 16 /* msg hdr */ + 4 /* par hdr */;
		    unsigned int req_size = c->send_alloc - req_off;
		    if (tl) {
			unsigned int b[4];
			int n = c->recv(c, b, tl);
			if (n < tl) {
			    c->in_cmd = 0;
			    rsc_abort(c, "Read error in parsing OOB_STREAM_READ parameters");
			    return -1;
			}
			/* FIXME: we need to fix endianness on bigendian machines - but this is true elewhere! */
			if (PAR_TYPE(b[0]) != DT_INT || PAR_LEN(b[0]) != sizeof(b[1]) || b[1] == 0)
			    err = ERR_inv_par;
			else {
			    /* we limit the request size */
			    if (b[1] < req_size) req_size = b[1];
			    /* flush the send buffer so it's guaranteed empty */
			    rsc_flush(c);
			    n = fread(c->send_buf + req_off, 1, req_size, c->stream);
			    if (n < 0) {
				err = ERR_IOerror;
				fclose(c->stream);
				c->stream = 0;
			    } else {
				unsigned int *sb = (unsigned int*) (c->send_buf);
				sb[0] = OOB_STREAM_READ | RESP_OK;
				sb[2] = sb[3] = 0;
				if (n) {
				    sb[1] = n + 4;
				    sb[4] = SET_PAR(DT_BYTESTREAM, n);
				    c->send_len = req_off + n;
				} else {
				    sb[1] = 0;
				    c->send_len = 16; /* jsut the header */
				}
				/* we have populated the send buffer by hand, jsut flush it */
				rsc_flush(c);
			    }			    
			}
		    }
		}
	    } else {
		rsc_slurp(c, tl);
		err = ERR_unsupportedCmd;
	    }
	    if (err) {
		rhdr.cmd = err | CMD_RESP;
		rsc_write(c, &rhdr, sizeof(rhdr));
		rsc_flush(c);
	    }
	} else break;
    }	
    c->in_cmd = 0;
    return tl;
}
#endif

static long get_hdr(SEXP sc, rsconn_t *c, struct phdr *hdr) {
    long tl = 0;
    while (1) {
	if (rsc_read(c, hdr, sizeof(*hdr)) != sizeof(*hdr)) {
	    c->in_cmd = 0;
	    RS_close(sc);
	    Rf_error("read error - could not obtain response header");
	}
#if LONG_MAX > 2147483647
	tl = hdr->res;
	tl <<= 32;
	tl |= hdr->len;
#else
	tl = hdr->len;
#endif
	if (hdr->cmd & CMD_OOB) {
	    SEXP res, ee = R_NilValue;
	    unsigned int *ibuf;
	    PROTECT(res = allocVector(RAWSXP, tl));
	    if (rsc_read(c, RAW(res), tl) != tl) {
		c->in_cmd = 0;
		RS_close(sc);
		Rf_error("read error in OOB message");
	    }
	    ibuf = (unsigned int*) RAW(res);
	    /* FIXME: we assume that we get encoded SEXP - we should check ... */
	    ibuf += 1;
	    res = QAP_decode(&ibuf);
	    UNPROTECT(1); /* original RAW res */
	    PROTECT(res); /* result */

	    /* FIXME: Rserve has a bug(?) that sets CMD_RESP on OOB commands so we clear it for now ... */
	    hdr->cmd &= ~CMD_RESP;

	    if (IS_OOB_SEND(hdr->cmd) && c->oob_send_cb != R_NilValue)
		PROTECT(ee = lang3(c->oob_send_cb, ScalarInteger(OOB_USR_CODE(hdr->cmd)), res));
	    if (IS_OOB_MSG(hdr->cmd) && c->oob_msg_cb != R_NilValue)
		PROTECT(ee = lang3(c->oob_msg_cb, ScalarInteger(OOB_USR_CODE(hdr->cmd)), res));
#ifdef RC_DEBUG
	    Rprintf(" - OOB %x %s (%d) %d\n", hdr->cmd, IS_OOB_SEND(hdr->cmd) ? "send" : "other", OOB_USR_CODE(hdr->cmd), (int) tl);
#endif
	    if (ee != R_NilValue) { /* OOB send or msg - we ignore anything else */
		res = eval(ee, R_GlobalEnv);
		if (IS_OOB_MSG(hdr->cmd)) {
		    struct phdr rhdr;
		    long pl = QAP_getStorageSize(res);
		    SEXP outv = PROTECT(allocVector(RAWSXP, pl));
		    int isx = pl > 0x7fffff;
		    unsigned int *oh = (unsigned int*) RAW(outv);
		    unsigned int *ot = QAP_storeSEXP(oh + (isx ? 2 : 1), res, pl);
		    pl = sizeof(int) * (long) (ot - oh);
		    rhdr.cmd = hdr->cmd | CMD_RESP;
		    rhdr.len = pl;
		    rhdr.dof = 0;
#ifdef __LP64__
		    rhdr.res = pl >> 32;
#else
		    rhdr.res = 0;
#endif
		    oh[0] = SET_PAR(DT_SEXP | (isx ? DT_LARGE : 0), pl - (isx ? 8 : 4));
		    if (isx) oh[1] = (pl - 8) >> 24;
		    rsc_write(c, &rhdr, sizeof(rhdr));
		    if (pl) rsc_write(c, RAW(outv), pl);
		    rsc_flush(c);
		    UNPROTECT(1); /* outv */
		}
		UNPROTECT(1); /* ee */
	    }
	    UNPROTECT(1); /* res */
	    continue;
	}
	break;
    }
    if (c->in_cmd) c->in_cmd--;
    if (hdr->cmd != RESP_OK) {
	rsc_slurp(c, tl);
	Rf_error("command failed with status code 0x%x: %s", CMD_STAT(hdr->cmd), rs_status_string(CMD_STAT(hdr->cmd)));
    }
    return tl;
}

SEXP RS_eval_qap(SEXP sc, SEXP what, SEXP sWait) {
    SEXP res = R_NilValue;
    rsconn_t *c;
    int async = (asInteger(sWait) == 0);

    if (!inherits(sc, "RserveConnection")) Rf_error("invalid connection");
    c = (rsconn_t*) EXTPTR_PTR(sc);
    if (!c) Rf_error("invalid NULL connection");
    if (!async && c->in_cmd) Rf_error("uncollected result from previous command, remove first");

    {
	struct phdr rhdr;
	long pl   = QAP_getStorageSize(what), tl;
	SEXP outv = PROTECT(allocVector(RAWSXP, pl));
	int isx   = pl > 0x7fffff;
	unsigned int *oh = (unsigned int*) RAW(outv);
	unsigned int *ot = QAP_storeSEXP(oh + (isx ? 2 : 1), what, pl);

	pl = sizeof(int) * (long) (ot - oh);
	rhdr.cmd = CMD_eval;
	/* If the call is OCref then it's OCcall and not eval ... */
	if (TYPEOF(what) == LANGSXP && inherits(CAR(what), "OCref")) rhdr.cmd = CMD_OCcall;
	rhdr.len = pl;
	rhdr.dof = 0;
#ifdef __LP64__
	rhdr.res = pl >> 32;
#else
	rhdr.res = 0;
#endif
	oh[0] = SET_PAR(DT_SEXP | (isx ? DT_LARGE : 0), pl - (isx ? 8 : 4));
	if (isx) oh[1] = (pl - 8) >> 24;
	rsc_write(c, &rhdr, sizeof(rhdr));
	if (pl) rsc_write(c, RAW(outv), pl);
	rsc_flush(c);
	UNPROTECT(1); /* outv */
	outv = 0;

	if (async) {
	    c->in_cmd++;
	    return R_NilValue;
	}
	tl = get_hdr(sc, c, &rhdr);
	res = PROTECT(allocVector(RAWSXP, tl));
	if (rsc_read(c, RAW(res), tl) != tl) {
	    RS_close(sc);
	    Rf_error("read error reading payload of the eval result");
	} else {
	    unsigned int *ibuf = (unsigned int*) RAW(res);
	    int par_type = PAR_TYPE(*ibuf);
	    int is_large = (par_type & DT_LARGE) ? 1 : 0;
	    if (is_large) par_type ^= DT_LARGE;
	    if (par_type != DT_SEXP)
		Rf_error("invalid result type coming from eval");
	    ibuf += is_large + 1;
	    res = QAP_decode(&ibuf);
	}
	UNPROTECT(1);
    }

    return res;
}

SEXP RS_eval(SEXP sc, SEXP what, SEXP sWait) {
    SEXP res;
    rsconn_t *c;
    struct phdr hdr;
    char *p = (char*) RAW(what);
    int pl = LENGTH(what), async = (asInteger(sWait) == 0);
    long tl;

    if (!inherits(sc, "RserveConnection")) Rf_error("invalid connection");
    c = (rsconn_t*) EXTPTR_PTR(sc);
    if (!c) Rf_error("invalid NULL connection");
    if (!async && c->in_cmd) Rf_error("uncollected result from previous command, remove first");
    hdr.cmd = CMD_serEval;
    hdr.len = pl;
    hdr.dof = 0;
    hdr.res = 0;
    rsc_write(c, &hdr, sizeof(hdr));
    rsc_write(c, p, pl);
    rsc_flush(c);
    if (async) {
	c->in_cmd++;
	return R_NilValue;
    }
    tl = get_hdr(sc, c, &hdr);
    res = PROTECT(allocVector(RAWSXP, tl));
    if (rsc_read(c, RAW(res), tl) != tl) {
	RS_close(sc);
	Rf_error("read error reading payload of the eval result");
    }
    UNPROTECT(1);
    return res;
}

SEXP RS_collect(SEXP sc, SEXP s_timeout) {
    double tout = asReal(s_timeout);
    int maxfd = 0, r;
    fd_set rset;
    struct timeval tv;
    FD_ZERO(&rset);
    if (TYPEOF(sc) == VECSXP) {
	int n = LENGTH(sc), i;
	for (i = 0; i < n; i++) {
	    SEXP cc = VECTOR_ELT(sc, i);
	    if (TYPEOF(cc) == EXTPTRSXP && inherits(cc, "RserveConnection")) {
		rsconn_t *c = (rsconn_t*) EXTPTR_PTR(cc);
		if (c && (c->in_cmd) && c->s != -1) {
		    if (c->s > maxfd) maxfd = c->s;
		    FD_SET(c->s, &rset);
		}
	    }
	}
    } else if (TYPEOF(sc) == EXTPTRSXP && inherits(sc, "RserveConnection")) {
	rsconn_t *c = (rsconn_t*) EXTPTR_PTR(sc);
	if (c && (c->in_cmd) && c->s != -1) {
	    if (c->s > maxfd) maxfd = c->s;
	    FD_SET(c->s, &rset);
	}
    } else Rf_error("invalid input - must be an Rserve connection or a list thereof");
    if (maxfd == 0) return R_NilValue;
    if (tout < 0.0 || tout > 35000000.0) tout = 35000000.0; /* roughly a year .. */
    tv.tv_sec = (int) tout;
    tv.tv_usec = (tout - (double) tv.tv_sec) * 1000000.0;
    r = select(maxfd + 1, &rset, 0, 0, &tv);
    if (r < 1) return R_NilValue; /* FIXME: we don't distinguish between error and timeout ... */
    {
	SEXP res;
	struct phdr hdr;
	long tl;
	rsconn_t *c;
	int rdy = -1;
	if (TYPEOF(sc) == EXTPTRSXP) /* there is only one so it must be us */
	    c = (rsconn_t*) EXTPTR_PTR(sc);
	else { /* find a connection that is ready */
	    int n = LENGTH(sc), i;
	    for (i = 0; i < n; i++) {
		SEXP cc = VECTOR_ELT(sc, i);
		if (TYPEOF(cc) == EXTPTRSXP && inherits(cc, "RserveConnection")) {
		    c = (rsconn_t*) EXTPTR_PTR(cc);
		    if (c && (c->in_cmd) && FD_ISSET(c->s, &rset))
			break;
		}
	    }	    
	    if (i >= n) return R_NilValue;
	    rdy = i;
	    sc = VECTOR_ELT(sc, rdy);
	}
	/* both sc and c are set to the node and the structure */
	tl = get_hdr(sc, c, &hdr);
	res = PROTECT(allocVector(RAWSXP, tl));
	setAttrib_(res, "rsc", sc);
	if (rdy >= 0) setAttrib_(res, "index", ScalarInteger(rdy + 1));
	if (rsc_read(c, RAW(res), tl) != tl) {
	    RS_close(sc);
	    Rf_error("read error reading payload of the eval result");
	}
	UNPROTECT(1);
	return res;
    }
}

SEXP RS_decode(SEXP sWhat) {
    unsigned int *ibuf = (unsigned int*) RAW(sWhat);
    int par_type = PAR_TYPE(*ibuf);
    int is_large = (par_type & DT_LARGE) ? 1 : 0;
    if (is_large) par_type ^= DT_LARGE;
    if (par_type != DT_SEXP)
	Rf_error("invalid result - must be DT_SEXP");
    ibuf += is_large + 1;
    /* FIXME: we don't check if we message is complete */
    return QAP_decode(&ibuf);
}

SEXP RS_assign(SEXP sc, SEXP what, SEXP sWait) {
    SEXP res;
    rsconn_t *c;
    struct phdr hdr;
    char *p = (char*) RAW(what);
    int pl = LENGTH(what), async = (asInteger(sWait) == 0);
    long tl;

    if (!inherits(sc, "RserveConnection")) Rf_error("invalid connection");
    c = (rsconn_t*) EXTPTR_PTR(sc);
    if (!c) Rf_error("invalid NULL connection");
    if (!async && c->in_cmd) Rf_error("uncollected result from previous command, remove first");
    hdr.cmd = CMD_serAssign;
    hdr.len = pl;
    hdr.dof = 0;
    hdr.res = 0;
    rsc_write(c, &hdr, sizeof(hdr));
    rsc_write(c, p, pl);
    rsc_flush(c);
    if (async) {
	c->in_cmd++;
	return R_NilValue;
    }
    tl = get_hdr(sc, c, &hdr);
    res = PROTECT(allocVector(RAWSXP, tl));
    if (rsc_read(c, RAW(res), tl) != tl) {
	RS_close(sc);
	Rf_error("read error reading payload of the eval result");
    }
    UNPROTECT(1);
    return res;
}

SEXP RS_ctrl_str(SEXP sc, SEXP sCmd, SEXP sPayload) {
    rsconn_t *c;
    const char *pl;
    struct phdr hdr;
    int cmd = asInteger(sCmd), pll, par;
    long tl;

    if (!inherits(sc, "RserveConnection")) Rf_error("invalid connection");
    c = (rsconn_t*) EXTPTR_PTR(sc);
    if (!c) Rf_error("invalid NULL connection");
    if (c->in_cmd) Rf_error("uncollected result from previous command, remove first");
    if (TYPEOF(sPayload) != STRSXP || LENGTH(sPayload) != 1)
	Rf_error("invalid control command payload - string expected"); 
    pl = CHAR(STRING_ELT(sPayload, 0));
    pll = strlen(pl);

    if ((cmd & (~ 0xf)) != CMD_ctrl)
	Rf_error("invalid command - must be a control command");
    
    hdr.cmd = cmd;
    hdr.len = pll + 5; /* payload + header + NUL */
    hdr.dof = 0;
    hdr.res = 0;
    rsc_write(c, &hdr, sizeof(hdr));
    par = SET_PAR(DT_STRING, pll + 1);
    rsc_write(c, &par, sizeof(par));
    rsc_write(c, pl, pll + 1);
    rsc_flush(c);
    tl = get_hdr(sc, c, &hdr);
    if (tl) {
	/* FIXME: we actually discard it so we could use slurp instead ..? */
	SEXP res = allocVector(RAWSXP, tl);
	if (rsc_read(c, RAW(res), tl) != tl) {
	    RS_close(sc);
	    Rf_error("read error reading payload of the result");
	}
    }
    if (CMD_FULL(hdr.cmd) == RESP_ERR)
	Rf_error("Rserve responded with an error code 0x%x: %s", CMD_STAT(hdr.cmd), rs_status_string(CMD_STAT(hdr.cmd)));
    else if (CMD_FULL(hdr.cmd) != RESP_OK)
	Rf_error("unknown response 0x%x", hdr.cmd);
	
    return ScalarLogical(TRUE);
}

SEXP RS_switch(SEXP sc, SEXP prot, SEXP sVerify, SEXP sChainFile, SEXP sKeyFile, SEXP sCAFile) {
    rsconn_t *c;

    if (!inherits(sc, "RserveConnection")) Rf_error("invalid connection");
    c = (rsconn_t*) EXTPTR_PTR(sc);
    if (!c) Rf_error("invalid NULL connection");
    if (c->in_cmd) Rf_error("uncollected result from previous command, remove first");
    const char *chain = ((TYPEOF(sChainFile) == STRSXP) && LENGTH(sChainFile) > 0) ? CHAR(STRING_ELT(sChainFile, 0)) : 0;
    const char *key = ((TYPEOF(sKeyFile) == STRSXP) && LENGTH(sKeyFile) > 0) ? CHAR(STRING_ELT(sKeyFile, 0)) : 0
;
    const char *ca = ((TYPEOF(sCAFile) == STRSXP) && LENGTH(sCAFile) > 0) ? CHAR(STRING_ELT(sCAFile, 0)) : 0;
    if (TYPEOF(prot) != STRSXP || LENGTH(prot) != 1)
	Rf_error("invalid protocol specification");
#ifdef USE_TLS
    if (!strcmp(CHAR(STRING_ELT(prot, 0)), "TLS")) {
	struct phdr hdr;
	int par;
	long tl;
	hdr.cmd = CMD_switch;
	hdr.len = 8;
	hdr.res = 0;
	hdr.dof = 0;
	par = SET_PAR(DT_STRING, 4);
	rsc_write(c, &hdr, sizeof(hdr));
	rsc_write(c, &par, sizeof(par));
	rsc_write(c, "TLS", 4);
	rsc_flush(c);
	tl = get_hdr(sc, c, &hdr);
	if (tl)
	    rsc_slurp(c, tl);
	if (tls_upgrade(c, asInteger(sVerify), chain, key, ca) != 1) {
	    RS_close(sc);
	    Rf_error("TLS negotitation failed");
	}
	return ScalarLogical(TRUE);
    }
#endif
    Rf_error("unsupported protocol");
    return R_NilValue;
}

SEXP RS_authkey(SEXP sc, SEXP type) {
    SEXP res;
    rsconn_t *c;
    struct phdr hdr;
    const char *key_type;
    int par;
    long tl;

    if (!inherits(sc, "RserveConnection")) Rf_error("invalid connection");
    c = (rsconn_t*) EXTPTR_PTR(sc);
    if (!c) Rf_error("invalid NULL connection");
    if (c->in_cmd) Rf_error("uncollected result from previous command, remove first");
    if (TYPEOF(type) != STRSXP || LENGTH(type) != 1)
	Rf_error("invalid key type specification");
    key_type = CHAR(STRING_ELT(type, 0));
    
    hdr.cmd = CMD_keyReq;
    hdr.len = strlen(key_type) + 5;
    hdr.dof = 0;
    hdr.res = 0;

    par = SET_PAR(DT_STRING, strlen(key_type) + 1);
    rsc_write(c, &hdr, sizeof(hdr));
    rsc_write(c, &par, sizeof(par));
    rsc_write(c, key_type, strlen(key_type) + 1);
    rsc_flush(c);
    tl = get_hdr(sc, c, &hdr);
    res = PROTECT(allocVector(RAWSXP, tl));
    if (rsc_read(c, RAW(res), tl) != tl ) {
	RS_close(sc);
	Rf_error("read error loading key payload");
    }
    UNPROTECT(1);
    return res;
}

static unsigned char secauth_buf[65536];

#ifdef USE_TLS
static int RSA_encrypt(RSA *rsa, const unsigned char *src, unsigned char *dst, int len) {
    int i = 0, j = 0;
    while (len > 0) {
	int blk = (len > RSA_size(rsa) - 42) ? (RSA_size(rsa) - 42) : len;
	int eb = RSA_public_encrypt(blk, src + i, dst + j, rsa, RSA_PKCS1_OAEP_PADDING);
	if (eb < blk) return -1;
	i += blk;
	j += eb;
	len -= blk;
    }
    return j;
}
#endif

SEXP RS_secauth(SEXP sc, SEXP auth, SEXP key) {
#ifdef USE_TLS
    rsconn_t *c;
    struct phdr hdr;
    unsigned char *r;
    const unsigned char *ptr;
    int l, n, on, al, par;
    long tl;
    RSA *rsa;

    if (!inherits(sc, "RserveConnection")) Rf_error("invalid connection");
    if (TYPEOF(key) != RAWSXP || LENGTH(key) < 16)
	Rf_error("invalid key");
    c = (rsconn_t*) EXTPTR_PTR(sc);
    if (!c) Rf_error("invalid NULL connection");
    if (c->in_cmd) Rf_error("uncollected result from previous command, remove first");
    if (!((TYPEOF(auth) == STRSXP && LENGTH(auth) == 1) || (TYPEOF(auth) == RAWSXP)))
	Rf_error("invalid auhtentication token");
    r = (unsigned char*) RAW(key);
    l = ((int) r[0]) | (((int) r[1]) << 8) | (((int) r[2]) << 16) | (((int) r[3]) << 24);
    if (l + 8 > LENGTH(key))
	Rf_error("invalid key");
    if (l > 17000)
	Rf_error("authkey is too big for this client");
    n = ((int) r[l + 4]) | (((int) r[l + 5]) << 8) | (((int) r[l + 6]) << 16) | (((int) r[l + 7]) << 24);
    /* Rprintf("l = %d, n = %d, sum = %d (length %d)\n", l, n, l + n + 8, LENGTH(key)); */
    if (l + n + 8 > LENGTH(key)) 
	Rf_error("invalid key");
    ptr = r + l + 8;
    if (first_tls)
	init_tls();
    rsa = d2i_RSAPublicKey(0, &ptr, n);
    if (!rsa)
	Rf_error("the key has no valid RSA public key: %s", ERR_error_string(ERR_get_error(), 0));
    memcpy(secauth_buf, r, l + 4);
    if (TYPEOF(auth) == STRSXP) {
	const char *ak = translateCharUTF8(STRING_ELT(auth, 0));
	al = strlen(ak) + 1;
	if (al > 4096)
	    Rf_error("too long authentication token");
	memcpy(secauth_buf + l + 8, ak, al);
    } else {
	al = LENGTH(auth);
	if (al > 4096)
	    Rf_error("too long authentication token");
	memcpy(secauth_buf + l + 8, RAW(auth), al);
    }
    secauth_buf[l + 4] = al & 255;
    secauth_buf[l + 5] = (al >> 8) & 255;
    secauth_buf[l + 6] = (al >> 16) & 255;
    secauth_buf[l + 7] = (al >> 24) & 255;
    on = RSA_encrypt(rsa, secauth_buf, secauth_buf + 32768, l + al + 8);
    if (on < l + al + 8)
	Rf_error("failed to encrypt authentication packet (%s)", ERR_error_string(ERR_get_error(), 0));

    hdr.cmd = CMD_secLogin;
    hdr.len = on + 4;
    hdr.res = 0;
    hdr.dof = 0;
    
    par = SET_PAR(DT_BYTESTREAM, on);

    rsc_write(c, &hdr, sizeof(hdr));
    rsc_write(c, &par, sizeof(par));
    rsc_write(c, secauth_buf + 32768, on);
    rsc_flush(c);
    tl = get_hdr(sc, c, &hdr);
    if (tl)
	rsc_slurp(c, tl);
    return ScalarLogical(TRUE);
#else
    Rf_error("RSA is not supported in this build of the client - recompile with OpenSLL");
    return R_NilValue;
#endif
}

SEXP RS_oob_cb(SEXP sc, SEXP send_cb, SEXP msg_cb, SEXP query) {
    rsconn_t *c;
    SEXP res;
    int read_only = (asInteger(query) == 1);
    if (!inherits(sc, "RserveConnection")) Rf_error("invalid connection");
    c = (rsconn_t*) EXTPTR_PTR(sc);
    if (!c) Rf_error("invalid NULL connection");
    if (!read_only) {
	if (send_cb != c->oob_send_cb) {
	    if (c->oob_send_cb != R_NilValue)
		R_ReleaseObject(c->oob_send_cb);
	    c->oob_send_cb = send_cb;
	    if (send_cb != R_NilValue)
		R_PreserveObject(send_cb);
	}
	if (msg_cb != c->oob_msg_cb) {
	    if (c->oob_msg_cb != R_NilValue)
		R_ReleaseObject(c->oob_msg_cb);
	    c->oob_msg_cb = msg_cb;
	    if (msg_cb != R_NilValue)
		R_PreserveObject(msg_cb);
	}
    }
    PROTECT(res = Rf_mkNamed(VECSXP, (const char *[]) { "send", "msg", "" }));
    SET_VECTOR_ELT(res, 0, c->oob_send_cb);
    SET_VECTOR_ELT(res, 1, c->oob_msg_cb);
    UNPROTECT(1);
    return res;    
}

SEXP RS_eq(SEXP s1, SEXP s2) {
    if (!inherits(s1, "RserveConnection") || !inherits(s2, "RserveConnection")) return ScalarLogical(FALSE);
    return ScalarLogical((EXTPTR_PTR(s1) == EXTPTR_PTR(s2)) ? TRUE : FALSE);
}

SEXP RS_print(SEXP sc) {
    rsconn_t *c;
    if (!inherits(sc, "RserveConnection")) Rf_error("invalid connection");
    c = (rsconn_t*) EXTPTR_PTR(sc);
    if (!c)
	Rprintf(" <NULL> **invalid** RserveConnection\n");
    else if (c->s == -1)
	Rprintf(" Closed Rserve connection %p\n", c);
    else
	Rprintf(" Rserve %s connection %p (socket %d, queue length %d)\n", c->tls ? "TLS/QAP1" : "QAP1", c, c->s, c->in_cmd);
    return sc;
}

/* --- asynchronous API --- */
#ifdef USE_THREADS

int rsc_handshake(rsconn_t *c) {
    char idstr[32];    
    if (rsc_read(c, idstr, 32) != 32) {
	if (c->thread) c->thread = ACS_HSERR;
	rsc_abort(c, "Handshake failed - ID string not received");
	return -1;
    }    
    if (memcmp(idstr, "Rsrv", 4) || memcmp(idstr + 8, "QAP1", 4)) {
	if (c->thread) c->thread = ACS_HSERR;
	rsc_abort(c, "Handshake failed - unknown protocol");
	return -1;
    }
    /* supported range 0100 .. 0103 */
    if (memcmp(idstr + 4, "0100", 4) < 0 || memcmp(idstr + 4, "0103", 4) > 0) {
	if (c->thread) c->thread = ACS_HSERR;
	rsc_abort(c, "Handshake failed - server protocol version too high");
	return -1;
    }
    return 0;
}

static void *rsc_async_thread(void *par) {
    rsconn_t *c = (rsconn_t*) par;
    
    if (!c) return c;
    c = rsc_connect_ex(c->host, c->port, c);
    if (!c) return c;
    if (rsc_handshake(c)) return 0;

    return 0;
}

SEXP RS_connect_async(SEXP sHost, SEXP sPort, SEXP useTLS) {
    int port = asInteger(sPort), use_tls = (asInteger(useTLS) == 1);
    const char *host;
    rsconn_t *c;
    SEXP res;

    if (port < 0 || port > 65534)
	Rf_error("Invalid port number");
#ifdef WIN32
    if (!port)
	Rf_error("unix sockets are not supported in Windows");
#endif
#ifndef USE_TLS
    if (use_tls)
	Rf_error("TLS is not supported in this build - recompile with OpenSSL");
#endif
    if (sHost == R_NilValue && !port)
	Rf_error("socket name must be specified in socket mode");
    if (sHost == R_NilValue)
	host = "127.0.0.1";
    else {
	if (TYPEOF(sHost) != STRSXP || LENGTH(sHost) != 1)
	    Rf_error("host must be a character vector of length one");
	host = R2UTF8(sHost);
    }
    c = rsc_alloc();
    if (!c)
	Rf_error("cannot allocate memory");

    c->host = strdup(host);
    c->port = port;
    c->thread = ACS_CONNECTING;

    if (sbthread_create(rsc_async_thread, c)) {
	rsc_close(c);
	Rf_error("cannot create thread for the connection");
    }

    res = PROTECT(R_MakeExternalPtr(c, R_NilValue, R_NilValue));
    setAttrib(res, R_ClassSymbol, mkString("RserveAsyncConnection"));
    R_RegisterCFinalizer(res, rsconn_fin);
    UNPROTECT(1);
    return res;
}

#endif
