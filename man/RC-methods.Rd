\name{RC-methods}
\alias{RC-methods}
\alias{print.RserveConnection}
\alias{==.RserveConnection}
\alias{!=.RserveConnection}
\title{
  Methods for the RserveConnection class
}
\description{
  Basic methods (printing, comparison) for the RserveConnection class.
}
\usage{
\S3method{print}{RserveConnection}(x, ...)
\S3method{==}{RserveConnection}(e1, e2)
\S3method{!=}{RserveConnection}(e1, e2)
}
\arguments{
  \item{x}{Rserve connection object}
  \item{e1}{Rserve connection object}
  \item{e2}{Rserve connection object}
  \item{\dots}{ignored}
}
%\details{
%}
\value{
  \code{print} returns \code{x} invisibly

  \code{==} and \code{!=} return a logical scalar
}
%\references{
%}
\author{
  Simon Urbanek
}
%\note{
%}
%\examples{
%}
\keyword{interface}
