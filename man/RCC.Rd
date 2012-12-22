\name{RCC}
\title{Functions to talk to an Rserve instance (new version)}
\alias{RCC}
\alias{RS.connect}
\alias{RS.close}
\alias{RS.eval}
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
RS.connect(host = NULL, port = 6311L, tls = FALSE, proxy.target = NULL,
           proxy.wait = TRUE)
RS.login(rsc, user, password, pubkey, authkey)
RS.eval(rsc, x, wait = TRUE)
RS.collect(rsc, timeout = Inf, detail = FALSE)
RS.close(rsc)
RS.assign(rsc, name, value, wait = TRUE)
RS.switch(rsc, protocol = "TLS")
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
  \item{tls}{if \code{TRUE} then SSL/TLS encrypted connection is started}
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
  \item{timeout}{timeout (in seconds) to wait before giving up}
  \item{detail}{if \code{TRUE} then the result payload is returned in a
    list with elements \code{value} (unserialized result value of the
    command - where applciable) and \code{rsc} (connection which
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

  \code{RS.server.eval} \code{RS.server.source} \code{RS.server.shutdown} 
}
\examples{
\dontrun{
  c <- RS.connect()
  RS.eval(c, data(stackloss))
  RS.eval(c, library(MASS))
  RS.eval(c, rlm(stack.loss ~ ., stackloss)$coeff)
  RS.eval(c, getwd())
  RS.close(c)
  }
}
\author{Simon Urbanek}
\keyword{interface}
