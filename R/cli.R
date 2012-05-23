RS.connect <- function(host=NULL, port=6311L, tls=FALSE) .Call("RS_connect", host, port, tls, PACKAGE="RSclient")

RS.close <- function(rsc) .Call("RS_close", rsc)

RS.eval <- function(rsc, x) unserialize(.Call("RS_eval", rsc, serialize(substitute(x), NULL, FALSE), PACKAGE="RSclient"))

RS.switch <- function(rsc, protocol="TLS") .Call("RS_switch", rsc, protocol, PACKAGE="RSclient")

RS.authkey <- function(rsc, type="rsa-authkey") .Call("RS_authkey", rsc, type, PACKAGE="RSclient")

RS.login <- function(rsc, user, password, pubkey, authkey) {
  if (missing(user) || missing(password)) stop("user and password must be specified")
  .Call("RS_secauth", rsc, paste(c(user, password, ''), collapse="\n"), authkey)
}
