RS.connect <- function(host=NULL, port=6311L) .Call("RS_connect", host, port, PACKAGE="RSclient")

RS.close <- function(rsc) .Call("RS_close", rsc)

RS.eval <- function(rsc, x) unserialize(.Call("RS_eval", rsc, serialize(substitute(x), NULL, FALSE), PACKAGE="RSclient"))
