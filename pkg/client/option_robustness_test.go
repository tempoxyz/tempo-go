package client

import (
	"net/http"
	"testing"
	"time"
)

// WithHTTPClient(nil) must not leave the client in a nil state.
func TestNew_NilHTTPClientIsIgnored(t *testing.T) {
	c := New("http://example.invalid", WithHTTPClient(nil))
	if c.httpClient == nil {
		t.Fatal("httpClient is nil after WithHTTPClient(nil)")
	}
	// Combined with WithTimeout, the constructor must not panic.
	c2 := New("http://example.invalid", WithHTTPClient(nil), WithTimeout(5*time.Second))
	if c2.httpClient == nil || c2.httpClient.Timeout != 5*time.Second {
		t.Fatalf("expected 5s timeout on a non-nil client, got %+v", c2.httpClient)
	}
}

// WithTimeout must survive a later WithHTTPClient (order-independent).
func TestNew_TimeoutSurvivesLaterHTTPClient(t *testing.T) {
	custom := &http.Client{Timeout: 99 * time.Second}
	c := New("http://example.invalid", WithTimeout(3*time.Second), WithHTTPClient(custom))
	if c.httpClient.Timeout != 3*time.Second {
		t.Fatalf("explicit WithTimeout was discarded: got %s", c.httpClient.Timeout)
	}
}

// A custom client without an explicit WithTimeout keeps its own timeout.
func TestNew_CustomClientTimeoutPreserved(t *testing.T) {
	custom := &http.Client{Timeout: 42 * time.Second}
	c := New("http://example.invalid", WithHTTPClient(custom))
	if c.httpClient.Timeout != 42*time.Second {
		t.Fatalf("custom client timeout not preserved: got %s", c.httpClient.Timeout)
	}
}

// The default client still gets the default timeout.
func TestNew_DefaultTimeout(t *testing.T) {
	c := New("http://example.invalid")
	if c.httpClient.Timeout != defaultTimeout {
		t.Fatalf("expected default timeout %s, got %s", defaultTimeout, c.httpClient.Timeout)
	}
}
