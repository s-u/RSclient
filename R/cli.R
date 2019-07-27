RS.connect <- function(host=NULL, port=6311L, tls=FALSE, verify=TRUE, proxy.target=NULL, proxy.wait=TRUE) .Call(RS_connect, host, port, tls, proxy.target, proxy.wait, verify)

RS.close <- function(rsc) .Call(RS_close, rsc)

RS.eval <- function(rsc, x, wait=TRUE, lazy=TRUE) { r <- .Call(RS_eval, rsc, serialize(if (isTRUE(lazy)) substitute(x) else x, NULL, FALSE), wait); if (is.raw(r)) unserialize(r) else r }

RS.eval.qap <- function(rsc, x, wait=TRUE) .Call(RS_eval_qap, rsc, x, wait)

RS.collect <- function(rsc, timeout = Inf, detail = FALSE, qap = FALSE) {
    r <- .Call(RS_collect, rsc, timeout)
    if (is.raw(r)) {
        if (length(r)) {
            val <- if (qap) .Call(RS_decode, r) else unserialize(r)
            if (isTRUE(detail))
                list(value = val, rsc = attr(r, "rsc"))
            else val
        } else if (isTRUE(detail))
            list(rsc = attr(r, "rsc"))
        else NULL
    } else r
}

RS.server.eval <- function(rsc, text) .Call(RS_ctrl_str, rsc, 0x42L, text)

RS.server.source <- function(rsc, filename) .Call(RS_ctrl_str, rsc, 0x45L, filename)

RS.server.shutdown <- function(rsc) .Call(RS_ctrl_str, rsc, 0x44L, "")

RS.switch <- function(rsc, protocol="TLS", verify=TRUE) .Call(RS_switch, rsc, protocol, verify)

RS.authkey <- function(rsc, type="rsa-authkey") .Call(RS_authkey, rsc, type)

RS.assign <- function(rsc, name, value, wait = TRUE) {
  if (missing(value)) {
    sym.name <- deparse(substitute(name))
    value <- name
    name <- sym.name
  }
  .Call(RS_assign, rsc, serialize(list(name, value), NULL), wait)
}

RS.login <- function(rsc, user, password, pubkey, authkey) {
  if (missing(user) || missing(password)) stop("user and password must be specified")
  .Call(RS_secauth, rsc, paste(c(user, password, ''), collapse="\n"), authkey)
}

RS.oobCallbacks <- function(rsc, send, msg) {
  if (missing(send) && missing(msg)) return(.Call(RS_oob_cb, rsc, NULL, NULL, TRUE))
  if (missing(send) || missing(msg)) {
    l <- .Call(RS_oob_cb, rsc, NULL, NULL, TRUE)
    if (missing(send)) send <- l$send
    if (missing(msg))  msg <- l$msg
  }
  invisible(.Call(RS_oob_cb, rsc, send, msg, FALSE))  
}

print.RserveConnection <- function(x, ...) invisible(.Call(RS_print, x))
`==.RserveConnection` <- function(e1, e2) .Call(RS_eq, e1, e2)
`!=.RserveConnection` <- function(e1, e2) !.Call(RS_eq, e1, e2)
