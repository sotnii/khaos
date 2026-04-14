package spec

import "time"

type Probe interface {
	isProbe()
}

type HTTPMethod string

const (
	HTTPMethodGet  HTTPMethod = "GET"
	HTTPMethodHead HTTPMethod = "HEAD"
)

type HTTPProbe struct {
	Method  HTTPMethod
	Path    string
	Port    int
	Code    int
	Timeout time.Duration
}

func (HTTPProbe) isProbe() {}
