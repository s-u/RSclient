RS.connect <- function(host=NULL, port=6311L, tls=FALSE) .Call("RS_connect", host, port, tls, PACKAGE="RSclient")

RS.close <- function(rsc) .Call("RS_close", rsc)

RS.eval <- function(rsc, x, wait=TRUE) { r <- .Call("RS_eval", rsc, serialize(substitute(x), NULL, FALSE), wait, PACKAGE="RSclient"); if (is.raw(r)) unserialize(r) else r }

RS.collect <- function(rsc, timeout = Inf) { r <- .Call("RS_collect", rsc, timeout, PACKAGE="RSclient"); if (is.raw(r)) unserialize(r) else r }

RS.switch <- function(rsc, protocol="TLS") .Call("RS_switch", rsc, protocol, PACKAGE="RSclient")

RS.authkey <- function(rsc, type="rsa-authkey") .Call("RS_authkey", rsc, type, PACKAGE="RSclient")

RS.assign <- function(rsc, name, value) .Call("RS_assign", rsc, serialize(list(name, value), NULL), PACKAGE="RSclient")

RS.login <- function(rsc, user, password, pubkey, authkey) {
  if (missing(user) || missing(password)) stop("user and password must be specified")
  .Call("RS_secauth", rsc, paste(c(user, password, ''), collapse="\n"), authkey, PACKAGE="RSclient")
}

RS.oobCallbacks <- function(rsc, send, msg) {
  if (missing(send) && missing(msg)) return(.Call("RS_oob_cb", rsc, NULL, NULL, TRUE))
  if (missing(send) || missing(msg)) {
    l <- .Call("RS_oob_cb", rsc, NULL, NULL, TRUE, PACKAGE="RSclient")
    if (missing(send)) send <- l$send
    if (missing(msg))  msg <- l$msg
  }
  invisible(.Call("RS_oob_cb", rsc, send, msg, FALSE, PACKAGE="RSclient"))  
}
