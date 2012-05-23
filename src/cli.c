/*
   (C)Copyright 2012 Simon Urbanek.

   Released under GPL v2, no warranties.

*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#ifdef WIN32
#include <windows.h>
#include <winsock2.h>
static int wsock_up = 0;
#else
#define closesocket(C) close(C)
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#include <unistd.h>
#include <sys/time.h>

#define USE_RINTERNALS
#include <Rinternals.h>

typedef struct rsconn {
    int s;
    unsigned int send_len, send_alloc;
    char *send_buf;
} rsconn_t;

#define rsc_ok(X) (((X)->s) != -1)

static rsconn_t *rsc_connect(const char *host, int port) {
    rsconn_t *c = (rsconn_t*) malloc(sizeof(rsconn_t));
    int family;
#ifdef WIN32
    if (!wsock_up) {
	 WSADATA dt;
	 /* initialize WinSock 2.0 (WSAStringToAddress is 2.0 feature) */
	 WSAStartup(0x0200, &dt);
	 wsock_up = 1;
    }
#endif
    c->s = -1;
    c->send_alloc = 65536;
    c->send_len = 0;
    c->send_buf = (char*) malloc(c->send_alloc);
    if (!c->send_buf) { free(c); return 0; }
#ifdef WIN32
    family = AF_INET;
#else
    family = port ? AF_INET : AF_LOCAL;
#endif
    c->s = socket(family, SOCK_STREAM, 0);
    if (c->s != -1) {
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
    if (c->s != -1)
	closesocket(c->s);
    c->s = -1;
    REprintf("rsc_abort: %s\n", reason);
    return -1;
}

static void rsc_flush(rsconn_t *c) {
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
	       (n = send(c->s, c->send_buf + sp, c->send_len - sp, 0)) > 0)
	    sp += n;
	if (sp < c->send_len)
	    rsc_abort(c, "send error");
    }
    c->send_len = 0;
}

static void rsc_close(rsconn_t *c) {
    if (!c) return;
    if (c->s != -1) {
	rsc_flush(c);
	closesocket(c->s);
    }
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
	int n = recv(c->s, ptr, needed, 0);
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
	int n = recv(c->s, slurp_buffer, (needed > sizeof(slurp_buffer)) ? sizeof(slurp_buffer) : needed, 0);
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

SEXP RS_connect(SEXP sHost, SEXP sPort) {
    int port = asInteger(sPort);
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
    /* we can't use rsc_close because it frees the connection object */
    closesocket(c->s);
    c->s = -1;
    return R_NilValue;
}

/* Rserve protocol */

#include "RSprotocol.h"

SEXP RS_eval(SEXP sc, SEXP what) {
    SEXP res;
    rsconn_t *c;
    struct phdr hdr;
    char *p = (char*) RAW(what);
    int pl = LENGTH(what);
    long tl;

    if (!inherits(sc, "RserveConnection")) Rf_error("invalid connection");
    c = (rsconn_t*) EXTPTR_PTR(sc);
    hdr.cmd = CMD_serEval;
    hdr.len = pl;
    hdr.dof = 0;
    hdr.res = 0;
    if (rsc_write(c, &hdr, sizeof(hdr)) != sizeof(hdr) ||
	rsc_write(c, p, pl) != pl)
	Rf_error("write error");
    rsc_flush(c);
    while (1) {
	if (rsc_read(c, &hdr, sizeof(hdr)) != sizeof(hdr)) {
	    RS_close(sc);
	    Rf_error("read error - could not obtain response header");
	}
	tl = hdr.res;
	tl <<= 32;
	tl |= hdr.len;
	if (hdr.cmd & CMD_OOB) {
	    rsc_slurp(c, hdr.len);
	    Rf_warning("out of band message - removing from the queue");
	    continue;
	}
	break;
    }
    if (hdr.cmd != RESP_OK) {
	rsc_slurp(c, tl);
	Rf_error("eval failed with status code %d", CMD_STAT(hdr.cmd));
    }
    res = allocVector(RAWSXP, tl);
    if (rsc_read(c, RAW(res), tl) != tl) {
	RS_close(sc);
	Rf_error("read error reading payload of the eval result");
    }
    return res;
}
