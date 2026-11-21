// Coraza + OWASP CRS inspection proxy.
//
// Sits between the traffic generator and the demo API. Every request is run
// through Coraza with the real OWASP Core Rule Set, and the verdict is added to
// the response as headers:
//
//	X-WAF-Score  total CRS inbound anomaly score
//	X-WAF-Rules  ids of the CRS detection rules that matched
//	X-WAF-Block  1 if CRS would have blocked the request, else 0
//
// The request is ALWAYS forwarded to the API ("monitor" mode), so the traffic
// behaves exactly as it did without a WAF and the dataset stays comparable.
//
// Config (environment): LISTEN, UPSTREAM, PARANOIA (CRS paranoia level 1-4),
// LOG_MATCHES=1 to print every matched rule.
package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
)

// Rule 949110 reports e.g. "Inbound Anomaly Score Exceeded (Total Score: 8)".
var totalScore = regexp.MustCompile(`Total Score: (\d+)`)

// CRS anomaly points per severity (CRS defaults).
func points(s types.RuleSeverity) int {
	switch s.String() {
	case "critical":
		return 5
	case "error":
		return 4
	case "warning":
		return 3
	case "notice":
		return 2
	}
	return 0
}

type verdict struct {
	score int
	rules []string
	block bool
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// CRS detection rules live in 910000-948999. 949xxx (blocking evaluation),
// 959xxx and 980xxx (reporting) are bookkeeping, not detections.
func isDetectionRule(id int) bool { return id >= 910000 && id < 949000 }

func inspect(waf coraza.WAF, r *http.Request) verdict {
	tx := waf.NewTransaction()
	defer tx.Close()

	tx.ProcessConnection(clientIP(r), 0, "127.0.0.1", 8080)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	for name, values := range r.Header {
		for _, v := range values {
			tx.AddRequestHeader(name, v)
		}
	}
	if r.Host != "" { // Go removes Host from r.Header
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}
	tx.ProcessRequestHeaders()

	if tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err == nil {
			r.Body = io.NopCloser(bytes.NewReader(body)) // restore for forwarding
			tx.WriteRequestBody(body)
		}
	}
	tx.ProcessRequestBody()
	tx.ProcessLogging() // runs phase 5, which contains the score-reporting rule

	var v verdict
	seen := map[int]bool{}
	sum, exact := 0, -1
	for _, mr := range tx.MatchedRules() {
		id := mr.Rule().ID()
		if id == 949110 || id == 949111 { // blocking evaluation: threshold reached
			v.block = true
			if m := totalScore.FindStringSubmatch(mr.Message()); m != nil {
				exact, _ = strconv.Atoi(m[1])
			}
		}
		// Skip bookkeeping rules (paranoia-level skips etc.): real detections have a severity.
		if p := points(mr.Rule().Severity()); isDetectionRule(id) && p > 0 && !seen[id] {
			seen[id] = true
			v.rules = append(v.rules, strconv.Itoa(id))
			sum += p
		}
	}
	if tx.IsInterrupted() {
		v.block = true
	}
	v.score = sum
	if exact >= 0 {
		v.score = exact // CRS's own total when it reached the blocking threshold
	}
	return v
}

func main() {
	listen := env("LISTEN", "127.0.0.1:8080")
	upstream := env("UPSTREAM", "http://127.0.0.1:8000")
	paranoia := env("PARANOIA", "1")
	inspectOnly := os.Getenv("INSPECT_ONLY") == "1" // 1: answer 204 + verdict headers, do not forward

	directives := fmt.Sprintf(`
Include @coraza.conf-recommended
Include @crs-setup.conf.example
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%s"
SecAction "id:900200,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'"
Include @owasp_crs/*.conf
SecRuleEngine On
SecAuditEngine Off
`, paranoia)

	cfg := coraza.NewWAFConfig().WithDirectives(directives).WithRootFS(coreruleset.FS)
	if os.Getenv("LOG_MATCHES") == "1" {
		cfg = cfg.WithErrorCallback(func(mr types.MatchedRule) { log.Print(mr.ErrorLog()) })
	}
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		log.Fatalf("cannot create WAF: %v", err)
	}

	target, err := url.Parse(upstream)
	if err != nil {
		log.Fatalf("bad UPSTREAM: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__waf_health" {
			io.WriteString(w, "ok")
			return
		}
		v := inspect(waf, r)
		block := "0"
		if v.block {
			block = "1"
		}
		h := w.Header()
		h.Set("X-WAF-Score", strconv.Itoa(v.score))
		h.Set("X-WAF-Rules", strings.Join(v.rules, ","))
		h.Set("X-WAF-Block", block)
		if inspectOnly { // side-car for the gateway: answer with the verdict, never touch the application
			w.WriteHeader(http.StatusNoContent)
			return
		}
		proxy.ServeHTTP(w, r) // always forward: monitor mode
	})

	log.Printf("Coraza+CRS proxy on %s -> %s (paranoia level %s)", listen, upstream, paranoia)
	log.Fatal(http.ListenAndServe(listen, nil))
}
