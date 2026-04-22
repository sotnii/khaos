package api

import (
	"net/http"
	"time"

	"github.com/sotnii/pakostii/internal/runtime/agent"
)

type Http struct {
	httpAgent agent.HttpAgent
}

type HttpResponse struct {
	Body       []byte
	StatusCode int
}

func NewHttp(httpAgent agent.HttpAgent) *Http {
	return &Http{httpAgent: httpAgent}
}

func (h *Http) Get(url string, timeout time.Duration) (*HttpResponse, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := h.httpAgent.Do(req, timeout)
	if err != nil {
		return nil, err
	}
	return &HttpResponse{
		Body:       res.Body,
		StatusCode: res.StatusCode,
	}, nil
}
