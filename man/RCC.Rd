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
%\alias{RSdetach}
%\alias{RSevalDetach}
%\alias{RSattach}
%\alias{RSshutdown}
%\alias{RSserverEval}
%\alias{RSserverSource}
\usage{
RS.connect(host = NULL, port = 6311L, tls = FALSE)
RS.login(rsc, user, password, pubkey, authkey)
RS.eval(rsc, x, wait = TRUE)
RS.collect(rsc, timeout = Inf)
RS.close(rsc)
RS.assign(rsc, name, value)
RS.switch(rsc, protocol = "TLS")
RS.authkey(rsc, type = "rsa-authkey")
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
  by R such as unix sockets, SSL/TLS connections, protocol switching and
  secure authentication.
}
\arguments{
  \item{host}{host to connect to or socket path or \code{NULL} for local host}
  \item{port}{TCP port to connect to or 0 if unix socket is to be used}
  \item{tls}{if \code{TRUE} then SSL/TLS encrypted connection is started}
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
  \item{name}{string, name of the symbol to assign to}
  \item{value}{value to assign}
  \item{protocol}{protocol to switch to (string)}
  \item{type}{type of the authentication to perform (string)}
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
  \code{RS.login(rsc, "username", "password", authkey=RS.authkey())}
  which ensures that the authentication request is encrypted and cannot
  be spoofed. When using TLS connections \code{RS.authkey} is not
  necessary as the connection is already encrypted.

  \code{RS.eval} evaluates the supplied expression remotely.

  \code{RS.collect} collects results from \code{RS.eval(..., wait =
    FALSE)} calls. Note that it this case \code{rsc} can be either one
  connection or a list of connections.

  \code{RS.assign} assigns a value to the remote global workspace.
  
  \code{RS.switch} attempts to switch the protocol currently used for
  communication with Rserve.
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
