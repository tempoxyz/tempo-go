package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"time"
)

// rateLimitTransport retries only explicit HTTP admission rejections. Network
// errors and server errors can have ambiguous transaction outcomes and are not retried.
type rateLimitTransport struct {
	base  http.RoundTripper
	delay time.Duration
}

func (t rateLimitTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	current := request
	for attempt := 0; ; attempt++ {
		response, err := t.base.RoundTrip(current)
		if err != nil || response.StatusCode != http.StatusTooManyRequests || attempt == 4 || request.GetBody == nil {
			return response, err
		}
		delay := t.delay << attempt
		if seconds, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && seconds > 0 && seconds <= 30 {
			delay = time.Duration(seconds) * time.Second
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
		timer := time.NewTimer(delay)
		select {
		case <-request.Context().Done():
			timer.Stop()
			return nil, request.Context().Err()
		case <-timer.C:
		}
		current = request.Clone(request.Context())
		current.Body, err = request.GetBody()
		if err != nil {
			return nil, err
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRateLimitTransport(t *testing.T) {
	for _, tt := range []struct {
		name         string
		status       int
		failures     int
		noReplay     bool
		networkError bool
		wantCalls    int
	}{
		{name: "replays rejected body", status: 429, failures: 2, wantCalls: 3},
		{name: "bounded retries", status: 429, failures: 10, wantCalls: 5},
		{name: "server failure", status: 500, failures: 1, wantCalls: 1},
		{name: "no replay body", status: 429, failures: 1, noReplay: true, wantCalls: 1},
		{name: "network failure", networkError: true, wantCalls: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			transport := rateLimitTransport{base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				require.Equal(t, "transaction", string(body))
				r.Body.Close()
				if tt.networkError {
					return nil, errors.New("connection reset")
				}
				status := http.StatusOK
				if calls <= tt.failures {
					status = tt.status
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("response"))}, nil
			})}
			request, err := http.NewRequest(http.MethodPost, "http://localhost", strings.NewReader("transaction"))
			require.NoError(t, err)
			if tt.noReplay {
				request.GetBody = nil
			}
			response, err := transport.RoundTrip(request)
			if tt.networkError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				defer response.Body.Close()
				wantStatus := http.StatusOK
				if tt.wantCalls <= tt.failures {
					wantStatus = tt.status
				}
				require.Equal(t, wantStatus, response.StatusCode)
				body, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				require.Equal(t, "response", string(body))
			}
			require.Equal(t, tt.wantCalls, calls)
		})
	}
}

func TestRateLimitTransportCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	transport := rateLimitTransport{delay: time.Hour, base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		r.Body.Close()
		cancel()
		return &http.Response{StatusCode: 429, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("rate limited"))}, nil
	})}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost", strings.NewReader("transaction"))
	require.NoError(t, err)
	_, err = transport.RoundTrip(request)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, calls)
}
