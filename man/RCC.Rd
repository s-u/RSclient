\name{RCC}
\title{Functions to talk to an Rserve instance (new version)}
\alias{RCC}
\alias{RS.connect}
\alias{RS.close}
\alias{RS.eval}
\alias{RS.eval.qap}
\alias{RS.login}
\alias{RS.switch}
\alias{RS.authkey}
\alias{RS.collect}
\alias{RS.assign}
\alias{RS.oobCallbacks}
%\alias{RSdetach}
%\alias{RSevalDetach}
%\alias{RSattach}
\alias{RS.server.shutdown}
\alias{RS.server.eval}
\alias{RS.server.source}
\usage{
RS.connect(host = NULL, port = 6311L, tls = FALSE, verify = TRUE,
           proxy.target = NULL, proxy.wait = TRUE, chain, key, ca)
RS.login(rsc, user, password, pubkey, authkey)
RS.eval(rsc, x, wait = TRUE, lazy = TRUE)
RS.eval.qap(rsc, x, wait = TRUE)
RS.collect(rsc, timeout = Inf, detail = FALSE, qap = FALSE)
RS.close(rsc)
RS.assign(rsc, name, value, wait = TRUE)
RS.switch(rsc, protocol = "TLS", verify = TRUE, chain, key, ca)
RS.authkey(rsc, type = "rsa-authkey")
RS.server.eval(rsc, text)
RS.server.source(rsc, filename)
RS.server.shutdown(rsc)
RS.oobCallbacks(rsc, send, msg)
}
\description{
  Rserve is a server providing R functionality via sockets. The
  following functions allow another R session to start new Rserve
  sessions and evaluate commands.
}
\note{
  The current version of the \code{RSclient} package supplies two
  clients - one documented in \code{\link{Rclient}} which uses R
  connections and one documented in \code{\link{RCC}} which uses C code
  and is far more versatile and efficient. This is the documentation for
  the latter which is new and supports features that are not supported
  by R such as unix sockets, SSL/TLS connections, protocol switching,
  secure authentication and multi-server collection.
}
\arguments{
  \item{host}{host to connect to or socket path or \code{NULL} for local host}
  \item{port}{TCP port to connect to or 0 if unix socket is to be used}
  \item{tls}{if \code{TRUE} then SSL/TLS encrypted connection is
    started}
  \item{verify}{logical, if \code{FALSE} no verification of the server
    certificate is done, otherwise the certificate is verified and the
    function will fail with an error if it is not valid.}
  \item{chain}{string, optional, path to a file in PEM format that contains
    client certificate and its chain. The client certificate must be
    first in the chain.}
  \item{key}{string, optional, path to a file in PEM format containing
    the private key for the client certificate. If a client certificate
    is necessary for the connection, both \code{chain} and \code{key}
    must be set.}
  \item{ca}{string, optional, path to a file holding any additional
    certificate authority (CA) certificates (including intermediate
    certificates) in PEM format that are required for the verification
    of the server certificate. Only relevant if \code{verify=TRUE}.
    If not set then it will be attempted to load the default trust
    store of the underlying library (which typically includes trusted
    root certificates).}
  \item{proxy.target}{proxy target (string) in the form \code{<host>:<port>}
    to be used when connecting to a non-transparent proxy that requires
    target designation. Not used when connected to transparent proxies
    or directly to Rserve instances. Note that literal IPv6 addresses must be
    quoted in \code{[]}.}
  \item{proxy.wait}{if \code{TRUE} then the proxy will wait (indefinitely) if the
    target is unavailable due to too high load, if \code{FALSE} then
    the proxy is instructed to close the connection in such instance instead}
  \item{rsc}{Rserve connection as obtained from \code{RS.connect}}
  \item{user}{username for authentication (mandatory)}
  \item{password}{password for authentication}
  \item{pubkey}{public key for authentication}
  \item{authkey}{authkey (as obtained from \code{RS.authkey}) for secure authentication}
  \item{x}{expression to evaluate}
  \item{wait}{if \code{TRUE} then the result is delivered synchronously,
    if \code{FALSE} then \code{NULL} is returned instead and the result
    can be collected later with \code{RS.collect}}
  \item{lazy}{if \code{TRUE} then the passed expression is not evaluated
    locally but passed for remote evaluation (as if quoted, modulo
    substitution). Otherwise it is evaluated locally first and the
    result is passed for remote evaluation.}
  \item{timeout}{numeric, timeout (in seconds) to wait before giving up}
  \item{detail}{if \code{TRUE} then the result payload is returned in a
    list with elements \code{value} (unserialized result value of the
    command - where applicable) and \code{rsc} (connection which
    returned this result) which allows to identify the source of the
    result and to distinguish timeout from a \code{NULL}
    value. Otherwise the returned value is just the payload value of the
    result.}
  \item{name}{string, name of the symbol to assign to}
  \item{value}{value to assign -- if missing \code{name} is assumed to
    be a symbol and its evaluated value will be used as value while the
    symbol name will be used as name}
  \item{protocol}{protocol to switch to (string)}
  \item{type}{type of the authentication to perform (string)}
  \item{send}{callback function for \code{OOB_SEND}}
  \item{msg}{callback function for \code{OOB_MSG}}
  \item{text}{string that will be parsed and evaluated on the server side}
  \item{filename}{name of the file (on the server!) to source}
  \item{qap}{logical, if \code{TRUE} then the result is assumed to be
    in QAP encoding (native Rserve protocol), otherwise it is assumed to
    be using R serialization.}
}
\details{
  \code{RS.connect} creates a connection to a Rserve. The returned handle
  is to be used in all subsequent calls to client functions. The session
  associated witht he connection is alive until closed via
  \code{RS.close}.

  \code{RS.close} closes the Rserve connection.

  \code{RS.login} performs authentication with the Rserve. The
  \code{user} entry is mandatory and at least one of \code{password},
  \code{pubkey} and \code{authkey} must be provided. Typical secure
  authentication is performed with
  \code{RS.login(rsc, "username", "password", authkey=RS.authkey(rsc))}
  which ensures that the authentication request is encrypted and cannot
  be spoofed. When using TLS connections \code{RS.authkey} is not
  necessary as the connection is already encrypted.

  \code{RS.eval} evaluates the supplied expression remotely.

  \code{RS.eval.qap} behaves like \code{RS.eval(..., lazy=FALSE)}, but
  uses the Rserve QAP serialization of R objects instead of the native R
  serialization.

  \code{RS.collect} collects results from \code{RS.eval(..., wait =
    FALSE)} calls. Note that in this case \code{rsc} can be either one
  connection or a list of connections.

  \code{RS.assign} assigns a value to the remote global workspace.
  
  \code{RS.switch} attempts to switch the protocol currently used for
  communication with Rserve. Currently the only supported protocol
  switch is from plain QAP1 to TLS secured (encrypted) QAP1.

  \code{RS.oobCallbacks} sets or retrieves the callback functions
  associated with \code{OOB_SEND} and \code{OOB_MSG} out-of-band
  commands. If neither \code{send} nor \code{msg} is specified then
  \code{RS.oobCallbacks} simply returns the current callback functions,
  otherwise it replaces the existing ones. Both functions have the form
  \code{function(code, payload)} where \code{code} is the OOB sub-code
  (scalar integer) and \code{payload} is the content passed in the OOB
  command. For \code{OOB_SEND} the result of the callback is disarded,
  for \code{OOB_MSG} the result is encoded and sent back to the
  server. Note that OOB commands in this client are only processed when
  waiting for the response to another command (typically
  \code{RS.eval}). OOB commands must be explicitly enabled in the
  server in order to be used (they are disabled by default).

  \code{RS.server.eval}, \code{RS.server.source} and
  \code{RS.server.shutdown} are `control commands' which are enqueued to
  be processed by the server asynchronously. They return \code{TRUE} on
  success which means the command was enqueued - it does not mean that
  the server has processed the command. All control commands affect only
  future connections, they do NOT affect any already established client
  connection (including the curretn one). \code{RS.server.eval} parses
  and evaluates the given code in the server instance,
  \code{RS.server.source} sources the given file in the server (the path
  is interpreted by the server, it is not the local path of the client!)
  and \code{RS.server.shutdown} attempts a clean shutdown of the
  server. Note that control commands are disabled by default and must be
  enabled in Rserve either in the configuration file with \code{control
  enable} or on the command line with \code{--RS-enable-control} (the
  latter only works with Rserve 1.7 and higher). If Rserve is configured
  with authentication enabled then only admin users can issues control
  commands (see Rserve documentation for details).
}
\examples{
\dontrun{
  c <- RS.connect()
  RS.eval(c, data(stackloss))
  RS.eval(c, library(MASS))
  RS.eval(c, rlm(stack.loss ~ ., stackloss)$coeff)
  RS.eval(c, getwd())
  x <- rnorm(1e5)
  ## this sends the contents of x to the remote side and runs `sum` on
  ## it without actually creating the binding x on the remote side
  RS.eval(c, as.call(list(quote(sum), x)), lazy=FALSE)
  RS.close(c)
  }
}
\author{Simon Urbanek}
\section{Parallel use}{
  It is currently possible to use Rserve connections in parallel via
  \code{mcparallel} or \code{mclapply} if certain conditions are
  met. First, only clear connection (non-TLS) are eligible for parallel
  use and there may be no OOB commands. Then it is legal to use
  connections in forked process as long as both the request is sent and
  the result is collected in the same process while no other process
  uses the connection. However, connections can only be created in the
  parent session (except if the connection is created and subsequently
  closed in the child process).

  One possible use is to initiate connections to a cluster and perform
  operations in parallel. For example:

  \preformatted{    library(RSclient)
    library(parallel)
    ## try to connect to 50 different nodes
    ## cannot parallelize this - must be in the parent process
    c <- lapply(paste("machine", 1:50, sep=''),
                function(name) try(RS.connect(name), silent=TRUE))
    ## keep only successful connections
    c <- c[sapply(c, class) == "RserveConnection"]
    ## login to all machines in parallel (using RSA secured login)
    unlist(mclapply(c,
           function(c) RS.login(c, "user", "password",, RS.authkey(c)),
	   mc.cores=length(c)))
    ## do parallel work ...
    ## pre-load some "job" function to all nodes
    unlist(mclapply(c, function(c) RS.assign(c, job), mc.cores=length(c)))
    ## etc. etc. then call it in parallel on all nodes ...
    mclapply(c, function(c) RS.eval(c, job()), mc.cores=length(c))
    
    ## close all
    sapply(c, RS.close)
  }
}
\note{
  The RSclient package can be compiled with TLS/SSL support based on
  OpenSSL. Therefore the following statements may be true if RSclient
  binaries are shipped together with OpenSSL: This product includes
  software developed by the OpenSSL Project for use in the OpenSSL
  Toolkit (http://www.openssl.org/). This product includes cryptographic
  software written by Eric Young (eay@cryptsoft.com). This product
  includes software written by Tim Hudson (tjh@cryptsoft.com).
  They are not true otherwise.
}
\keyword{interface}
