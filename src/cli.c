/*
   (C)Copyright 2012 Simon Urbanek.

   Released under GPL v2, no warranties.

*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <sys/types.h>
#ifdef WIN32
#include <windows.h>
#include <winsock2.h>
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

#ifdef USE_TLS
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#endif

#define USE_RINTERNALS
#include <Rinternals.h>

typedef struct rsconn {
    int s, intr, in_cmd;
    void *tls;
    unsigned int send_len, send_alloc;
    char *send_buf;
    int (*send)(struct rsconn *, const void *, int);
    int (*recv)(struct rsconn *, void *, int);
} rsconn_t;

#define rsc_ok(X) (((X)->s) != -1)

static int sock_send(rsconn_t *c, const void *buf, int len) {
    if (c->s == -1)
	Rf_error("connection is already closed");
    if (c->intr) {
	closesocket(c->s);
	c->s = -1;
	Rf_error("previous operation was interrupted, connection aborted");
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
	Rf_error("previous operation was interrupted, connection aborted");
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
static int tls_send(rsconn_t *c, const void *buf, int len) {
    return SSL_write((SSL*)c->tls, buf, len);
}

static int tls_recv(rsconn_t *c, void *buf, int len) {
    return SSL_read((SSL*)c->tls, buf, len);
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

static int tls_upgrade(rsconn_t *c) {
    SSL *ssl;
    SSL_CTX *ctx;
    if (first_tls)
	init_tls();
    ctx = SSL_CTX_new(SSLv23_client_method());
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    c->tls = ssl = SSL_new(ctx);
    c->send = tls_send;
    c->recv = tls_recv;
    SSL_set_fd(ssl, c->s);
    /* SSL_CTX_free(ctx) // check whether this is safe - it should be since ssl has the reference ... */
    return SSL_connect(ssl);
}
#endif


static rsconn_t *rsc_connect(const char *host, int port) {
    rsconn_t *c = (rsconn_t*) malloc(sizeof(rsconn_t));
    int family, connected = 0;
#ifdef WIN32
    if (!wsock_up) {
	 WSADATA dt;
	 /* initialize WinSock 2.0 (WSAStringToAddress is 2.0 feature) */
	 WSAStartup(0x0200, &dt);
	 wsock_up = 1;
    }
#endif
    c->intr = 0;
    c->s = -1;
    c->send_alloc = 65536;
    c->send_len = 0;
    c->send_buf = (char*) malloc(c->send_alloc);
    c->tls = 0;
    c->in_cmd = 0;
    c->send = sock_send;
    c->recv = sock_recv;
    if (!c->send_buf) { free(c); return 0; }
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
	setsockopt(c->s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
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

static int rsc_abort(rsconn_t *c, const char *reason) {
#if USE_TLS
    long tc = ERR_get_error();
    if (tc) {
	char *te = ERR_error_string(tc, 0);
	if (te) REprintf("TLS error: %s\n", te);
    }
#endif
    if (c->s != -1)
	closesocket(c->s);
    c->s = -1;
    c->in_cmd = 0;
    REprintf("rsc_abort: %s\n", reason);
    return -1;
}

static void rsc_flush(rsconn_t *c) {
    if (c->s == -1)
	Rf_error("connection lost");
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

/* --- R API -- */

#define R2UTF8(X) translateCharUTF8(STRING_ELT(X, 0))

static void rsconn_fin(SEXP what) {
    rsconn_t *c = (rsconn_t*) EXTPTR_PTR(what);
    if (c) rsc_close(c);
}

SEXP RS_connect(SEXP sHost, SEXP sPort, SEXP useTLS) {
    int port = asInteger(sPort), use_tls = (asInteger(useTLS) == 1);
    const char *host;
    char idstr[32];
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
    c = rsc_connect(host, port);
    if (!c)
	Rf_error("cannot connect to %s:%d", host, port);
#ifdef USE_TLS
    if (use_tls && tls_upgrade(c) != 1) {
	rsc_close(c);
	Rf_error("TLS handshake failed");
    }
#endif	
    if (rsc_read(c, idstr, 32) != 32) {
	rsc_close(c);
	Rf_error("Handshake failed - ID string not received");
    }
    if (memcmp(idstr, "Rsrv", 4) || memcmp(idstr + 8, "QAP1", 4)) {
	rsc_close(c);
	Rf_error("Handshake failed - unknown protocol");
    }

    /* supported range 0100 .. 0103 */
    if (memcmp(idstr + 4, "0100", 4) < 0 || memcmp(idstr + 4, "0103", 4) > 0) {
	rsc_close(c);
	Rf_error("Handshake failed - server protocol version too high");
    }

    res = PROTECT(R_MakeExternalPtr(c, R_NilValue, R_NilValue));
    setAttrib(res, R_ClassSymbol, mkString("RserveConnection"));
    R_RegisterCFinalizer(res, rsconn_fin);
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

/* Rserve protocol */

#include "RSprotocol.h"

static const char *rs_status_string(int status) {
    switch (status) {
    case 0: return "(status is OK)";
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
    case ERR_object_too_big: return "object too big";
    case ERR_out_of_mem: return "out of memory";
    case ERR_ctrl_closed: return "no control line present";
    case ERR_session_busy: return "session is busy";
    case ERR_detach_failed: return "unable to detach session";
    case ERR_disabled: return "feature is disabled";
    case ERR_unavailable: return "feature is not available in this build of the server";
    case ERR_cryptError: return "crypto-system error";
    case ERR_securityClose: return "connection aboted for security reasons";
    }
    return "(unknown error code)";
}

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
	    rsc_slurp(c, hdr->len);
	    Rf_warning("out of band message - removing from the queue");
	    continue;
	}
	break;
    }
    c->in_cmd = 0;
    if (hdr->cmd != RESP_OK) {
	rsc_slurp(c, tl);
	Rf_error("command failed with status code %d: %s", CMD_STAT(hdr->cmd), rs_status_string(CMD_STAT(hdr->cmd)));
    }
    return tl;
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
    if (c->in_cmd) Rf_error("uncollected result from previous command, remove first");
    hdr.cmd = CMD_serEval;
    hdr.len = pl;
    hdr.dof = 0;
    hdr.res = 0;
    rsc_write(c, &hdr, sizeof(hdr));
    rsc_write(c, p, pl);
    rsc_flush(c);
    if (async) {
	c->in_cmd = CMD_serEval;
	return R_NilValue;
    }
    tl = get_hdr(sc, c, &hdr);
    res = allocVector(RAWSXP, tl);
    if (rsc_read(c, RAW(res), tl) != tl) {
	RS_close(sc);
	Rf_error("read error reading payload of the eval result");
    }
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
		if (c && (c->in_cmd == CMD_serEval || c->in_cmd == CMD_serEEval) && c->s != -1) {
		    if (c->s > maxfd) maxfd = c->s;
		    FD_SET(c->s, &rset);
		}
	    }
	}
    } else if (TYPEOF(sc) == EXTPTRSXP && inherits(sc, "RserveConnection")) {
	rsconn_t *c = (rsconn_t*) EXTPTR_PTR(sc);
	if (c && (c->in_cmd == CMD_serEval || c->in_cmd == CMD_serEEval) && c->s != -1) {
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
	if (TYPEOF(sc) == EXTPTRSXP) /* there is only one so it must be us */
	    c = (rsconn_t*) EXTPTR_PTR(sc);
	else { /* find a connection that is ready */
	    int n = LENGTH(sc), i;
	    for (i = 0; i < n; i++) {
		SEXP cc = VECTOR_ELT(sc, i);
		if (TYPEOF(cc) == EXTPTRSXP && inherits(cc, "RserveConnection")) {
		    c = (rsconn_t*) EXTPTR_PTR(cc);
		    if (c && (c->in_cmd == CMD_serEval || c->in_cmd == CMD_serEEval) && FD_ISSET(c->s, &rset))
			break;
		}
	    }	    
	    if (i >= n) return R_NilValue;
	    sc = VECTOR_ELT(sc, i);
	}
	/* both sc and c are set to the node and the structure */
	tl = get_hdr(sc, c, &hdr);
	res = PROTECT(allocVector(RAWSXP, tl));
	setAttrib(res, install("rsc"), sc);
	if (rsc_read(c, RAW(res), tl) != tl) {
	    RS_close(sc);
	    Rf_error("read error reading payload of the eval result");
	}
	UNPROTECT(1);
	return res;
    }
}

SEXP RS_assign(SEXP sc, SEXP what) {
    SEXP res;
    rsconn_t *c;
    struct phdr hdr;
    char *p = (char*) RAW(what);
    int pl = LENGTH(what);
    long tl;

    if (!inherits(sc, "RserveConnection")) Rf_error("invalid connection");
    c = (rsconn_t*) EXTPTR_PTR(sc);
    if (!c) Rf_error("invalid NULL connection");
    if (c->in_cmd) Rf_error("uncollected result from previous command, remove first");
    hdr.cmd = CMD_serAssign;
    hdr.len = pl;
    hdr.dof = 0;
    hdr.res = 0;
    rsc_write(c, &hdr, sizeof(hdr));
    rsc_write(c, p, pl);
    rsc_flush(c);
    tl = get_hdr(sc, c, &hdr);
    res = allocVector(RAWSXP, tl);
    if (rsc_read(c, RAW(res), tl) != tl) {
	RS_close(sc);
	Rf_error("read error reading payload of the eval result");
    }
    return res;
}

SEXP RS_switch(SEXP sc, SEXP prot) {
    rsconn_t *c;

    if (!inherits(sc, "RserveConnection")) Rf_error("invalid connection");
    c = (rsconn_t*) EXTPTR_PTR(sc);
    if (!c) Rf_error("invalid NULL connection");
    if (c->in_cmd) Rf_error("uncollected result from previous command, remove first");
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
	if (tls_upgrade(c) != 1) {
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
    res = allocVector(RAWSXP, tl);
    if (rsc_read(c, RAW(res), tl) != tl ) {
	RS_close(sc);
	Rf_error("read error loading key payload");
    }
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
