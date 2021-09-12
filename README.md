# RSclient
## R-based client to Rserve

This R package provides a client for [Rserve](https://rforge.net/Rserve).
It started as a simple proof of concept (the `RSxx` functions which bypass Rserve serialization),
but was later re-written in C for high efficiency, full SSL/TLS and QAP support (the `RS.xx` functions).

It supports Rserve both in regular as well as in OCAP mode. The code could be used as a basis for C-level Rserve client if required.


[![CRAN](https://rforge.net/do/cransvg/RSclient)](https://cran.r-project.org/package=RSclient)
[![RForge](https://rforge.net/do/versvg/RSclient)](https://RForge.net/RSclient)
[![RSclient check](https://github.com/s-u/RSclient/actions/workflows/check.yml/badge.svg)](https://github.com/s-u/RSclient/actions/workflows/check.yml)


To install the CRAN version, use simply

```
install.packages("RSclient")
```

For installation of the latest development version, use

```
install.packages("RSclient", repo="https://rforge.net")
```
but note that you will require OpenSSL library and headers.
