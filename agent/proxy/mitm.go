package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/maximhq/bifrost/agent/config"
	"github.com/maximhq/bifrost/agent/tunnel"
)

// MITMProxy terminates TLS for intercepted AI API connections, rewrites HTTP
// headers to route through the Bifrost gateway, and relays responses back.
type MITMProxy struct {
	certStore       *CertStore
	forwarder       *Forwarder       // for gateway requests
	directForwarder *http.Client     // for direct relay (bypasses TUN)
	gatewayURL      string
	virtualKey      string
}

// NewMITMProxy creates a MITM proxy instance.
func NewMITMProxy(certStore *CertStore, gatewayURL string, virtualKey string) *MITMProxy {
	return &MITMProxy{
		certStore:  certStore,
		forwarder:  NewForwarder(),
		directForwarder: &http.Client{
			Timeout: 0, // no timeout for streaming
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					// Bypass TUN by dialing through the physical interface
					host, port, _ := net.SplitHostPort(addr)
					p := 443
					if port != "" {
						fmt.Sscanf(port, "%d", &p)
					}
					return tunnel.DialBypassTUN(host, p)
				},
				TLSClientConfig:     &tls.Config{},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
				ForceAttemptHTTP2:   true,
			},
		},
		gatewayURL: gatewayURL,
		virtualKey: virtualKey,
	}
}

// HandleConnection performs the full MITM flow on an intercepted TCP connection:
//  1. Generate a per-domain TLS certificate signed by the org CA
//  2. Complete the TLS handshake with the client
//  3. Read the HTTP request from the decrypted stream
//  4. Rewrite headers (inject x-bf-vk, change Host/URL to gateway)
//  5. Forward to the Bifrost gateway
//  6. Relay the gateway's response back through the TLS connection
func (p *MITMProxy) HandleConnection(conn net.Conn, hostname string, rule *config.DomainRule) {
	defer conn.Close()

	// Step 1: Get or generate a TLS certificate for this domain
	cert, err := p.certStore.GetOrCreate(hostname)
	if err != nil {
		log.Printf("cert generation failed for %s: %v", hostname, err)
		return
	}

	// Step 2: TLS handshake with the client, presenting our forged cert
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		// Advertise HTTP/1.1 and h2 — most AI APIs support both
		NextProtos: []string{"h2", "http/1.1"},
	}
	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake failed for %s: %v", hostname, err)
		return
	}
	defer tlsConn.Close()

	negotiatedProto := tlsConn.ConnectionState().NegotiatedProtocol

	// Step 3: Read HTTP request(s) from the decrypted stream.
	// Handle keep-alive by processing multiple requests on the same connection.
	if negotiatedProto == "h2" {
		// For HTTP/2, we need to use a different approach.
		// Fall back to HTTP/1.1 for now — most AI SDK clients accept it.
		// TODO: Implement full HTTP/2 MITM support.
		p.handleHTTP1(tlsConn, hostname, rule)
	} else {
		p.handleHTTP1(tlsConn, hostname, rule)
	}
}

// handleHTTP1 handles HTTP/1.1 requests on a MITM'd TLS connection.
// Supports keep-alive by processing multiple requests sequentially.
func (p *MITMProxy) handleHTTP1(tlsConn *tls.Conn, hostname string, rule *config.DomainRule) {
	reader := bufio.NewReader(tlsConn)

	for {
		// Read the HTTP request
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				log.Printf("HTTP read error from %s: %v", hostname, err)
			}
			return
		}

		// Set the original host in the request URL (ReadRequest doesn't populate this)
		if req.URL.Host == "" {
			req.URL.Host = hostname
		}
		if req.URL.Scheme == "" {
			req.URL.Scheme = "https"
		}

		originalPath := req.URL.Path

		shouldProxy := rule.ShouldProxyPath(originalPath)
		if shouldProxy {
			log.Printf("MATCH: %s %s%s → gateway", req.Method, hostname, originalPath)
		}

		// Check if this path should go through the Bifrost gateway or be
		// relayed directly to the origin (e.g., static assets for chatgpt.com)
		if shouldProxy {
			// Read request body for logging (buffer it so it can still be forwarded)
			var bodyBytes []byte
			if req.Body != nil {
				bodyBytes, err = io.ReadAll(req.Body)
				req.Body.Close()
				if err != nil {
					log.Printf("body read error for %s: %v", hostname, err)
					writeHTTPError(tlsConn, http.StatusBadGateway, "body read error")
					return
				}
				req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}

			// Log the proxied request with URL and payload
			logProxiedRequest(req.Method, hostname, originalPath, req.URL.RawQuery, bodyBytes)

			// --- Gateway path: rewrite headers and forward to Bifrost ---
			if err := RewriteRequest(req, rule, p.gatewayURL, p.virtualKey); err != nil {
				log.Printf("rewrite error for %s: %v", hostname, err)
				writeHTTPError(tlsConn, http.StatusBadGateway, "rewrite error")
				return
			}

			resp, err := p.forwarder.ForwardRoundTrip(req)
			if err != nil {
				log.Printf("gateway forward error for %s: %v", hostname, err)
				writeHTTPError(tlsConn, http.StatusBadGateway, "gateway error: "+err.Error())
				return
			}

			if err := writeHTTPResponse(tlsConn, resp); err != nil {
				log.Printf("response write error for %s: %v", hostname, err)
				resp.Body.Close()
				return
			}
			resp.Body.Close()
		} else {
			// --- Direct relay: forward to origin server bypassing TUN ---
			req.URL.Host = hostname
			req.URL.Scheme = "https"
			req.Host = hostname
			req.RequestURI = "" // required for http.Client

			resp, err := p.directForwarder.Do(req)
			if err != nil {
				log.Printf("direct relay error for %s%s: %v", hostname, originalPath, err)
				writeHTTPError(tlsConn, http.StatusBadGateway, "origin error: "+err.Error())
				return
			}

			if err := writeHTTPResponse(tlsConn, resp); err != nil {
				log.Printf("response write error for %s: %v", hostname, err)
				resp.Body.Close()
				return
			}
			resp.Body.Close()
		}

		// Check if the client wants to keep the connection alive
		if !shouldKeepAlive(req) {
			return
		}
	}
}

// writeHTTPResponse writes an HTTP response to a raw connection.
func writeHTTPResponse(w io.Writer, resp *http.Response) error {
	// Write status line
	statusLine := fmt.Sprintf("HTTP/%d.%d %d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, http.StatusText(resp.StatusCode))
	if _, err := w.Write([]byte(statusLine)); err != nil {
		return err
	}

	// Write headers
	for key, values := range resp.Header {
		for _, v := range values {
			if _, err := fmt.Fprintf(w, "%s: %s\r\n", key, v); err != nil {
				return err
			}
		}
	}
	if _, err := w.Write([]byte("\r\n")); err != nil {
		return err
	}

	// Stream the body, flushing for SSE support
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
			// Flush if the writer supports it (e.g., buffered writer)
			if f, ok := w.(*bufio.Writer); ok {
				f.Flush()
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// writeHTTPError writes an HTTP error response.
func writeHTTPError(w io.Writer, code int, msg string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(msg), msg)
	w.Write([]byte(resp))
}

// shouldKeepAlive returns true if the request wants a persistent connection.
func shouldKeepAlive(req *http.Request) bool {
	if req.Close {
		return false
	}
	conn := req.Header.Get("Connection")
	if strings.EqualFold(conn, "close") {
		return false
	}
	// HTTP/1.1 defaults to keep-alive
	return req.ProtoAtLeast(1, 1)
}

const maxPayloadLog = 2048 // truncate logged payloads to 2KB

// logProxiedRequest logs a proxied request with its URL and payload.
func logProxiedRequest(method, hostname, path, rawQuery string, body []byte) {
	url := "https://" + hostname + path
	if rawQuery != "" {
		url += "?" + rawQuery
	}

	if len(body) == 0 {
		log.Printf("PROXY: %s %s (no body)", method, url)
		return
	}

	payload := string(body)
	if len(payload) > maxPayloadLog {
		payload = payload[:maxPayloadLog] + fmt.Sprintf("... (%d bytes truncated)", len(body)-maxPayloadLog)
	}

	log.Printf("PROXY: %s %s\n  payload: %s", method, url, payload)
}
