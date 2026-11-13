package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// MaxBodyBytes caps a JSON request body read with DecodeJSON: API requests are small, and a
// huge body is refused before it is read into memory. Use DecodeJSONLimit for the rare
// endpoint that needs more.
const MaxBodyBytes = 16 << 10

// ErrBadJSON covers every way a request body can be unusable.
var ErrBadJSON = errors.New("request body must be one JSON object")

// DecodeJSON reads exactly one JSON object into dst. Unknown fields are ignored, so an
// older server accepts requests from a newer app; a missing or wrong Content-Type, a body
// over MaxBodyBytes, or trailing data is refused.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	return DecodeJSONLimit(w, r, dst, MaxBodyBytes)
}

// DecodeJSONLimit is DecodeJSON with another body limit (bytes).
func DecodeJSONLimit(w http.ResponseWriter, r *http.Request, dst any, limit int64) error {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		return ErrBadJSON
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	if err := dec.Decode(dst); err != nil {
		return ErrBadJSON
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrBadJSON
	}
	return nil
}

// WriteBadJSON answers an undecodable body.
func WriteBadJSON(w http.ResponseWriter) {
	WriteError(w, http.StatusBadRequest, "invalid_request", "send one JSON object with Content-Type: application/json")
}

// WriteInvalid answers a validation failure, naming each bad field and why.
func WriteInvalid(w http.ResponseWriter, fields map[string]string) {
	WriteJSON(w, http.StatusUnprocessableEntity, Error{Code: "invalid_fields", Fields: fields})
}

// WriteRateLimited answers 429 with the wait in both the header and the body.
func WriteRateLimited(w http.ResponseWriter, retry time.Duration) {
	secs := int(math.Ceil(retry.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	WriteJSON(w, http.StatusTooManyRequests, Error{Code: "rate_limited", RetryAfter: secs})
}

// WriteUnavailable answers 503 for a dependency that is down (database, Redis) or a busy
// password hasher: the client should retry shortly.
func WriteUnavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "2")
	WriteJSON(w, http.StatusServiceUnavailable, Error{Code: "temporarily_unavailable", RetryAfter: 2})
}

// WriteInternal answers 500 without any detail; the cause goes to the log.
func WriteInternal(w http.ResponseWriter) {
	WriteError(w, http.StatusInternalServerError, "internal", "")
}

// ---- who is calling --------------------------------------------------------------------

// Client is what a service knows about the device behind a request. The same endpoints serve the
// web and the Android and iOS apps; these headers tell them apart:
//
//	X-Client-Type: app              set by the apps (absent: web)
//	X-Client-Platform: android|ios  required with X-Client-Type: app
//	X-App-Version: 1.4.0 (212)      optional, cleaned and capped at 40 characters
//	X-Device-Id: <opaque>           required from apps (made on first launch, kept in the
//	                                Keychain/Keystore); optional on the web
//	X-Device-Name: Ray%E2%80%99s%20iPhone   optional, apps only: what "my devices" shows.
//	                                UTF-8, percent-encoded (encodeURIComponent), as headers
//	                                can't carry most characters; cleaned, at most 100
//
// The client IP comes from X-Hayitone-Client-Ip, which only the gateway can set (it strips
// every x-hayitone-* header clients send); without the gateway (local runs) it is the
// connection's address.
type Client struct {
	Type       string // "web", "android" or "ios"
	AppVersion string
	DeviceID   string
	DeviceName string     // apps only; "" when not sent or unusable
	IP         netip.Addr // invalid if unknown
	UserAgent  string
}

func (c Client) IsApp() bool { return c.Type != "web" }

// ErrClientHeaders means the app headers are present but inconsistent.
var ErrClientHeaders = errors.New("X-Client-Type app requires X-Client-Platform android|ios and an X-Device-Id")

// ClientFrom reads the client headers. Apps must send a platform and a device ID.
func ClientFrom(r *http.Request) (Client, error) {
	c := Client{
		Type:       "web",
		DeviceID:   cleanHeader(r.Header.Get("X-Device-Id"), 200),
		UserAgent:  cleanHeader(r.UserAgent(), 512),
		AppVersion: "",
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Client-Type")), "app") {
		switch strings.ToLower(strings.TrimSpace(r.Header.Get("X-Client-Platform"))) {
		case "android":
			c.Type = "android"
		case "ios", "iphone", "ipados":
			c.Type = "ios"
		default:
			return Client{}, ErrClientHeaders
		}
		if c.DeviceID == "" {
			return Client{}, ErrClientHeaders
		}
		c.AppVersion = cleanHeader(r.Header.Get("X-App-Version"), 40)
		c.DeviceName = deviceName(r.Header.Get("X-Device-Name"))
	}
	if ip, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Hayitone-Client-Ip"))); err == nil {
		c.IP = ip.Unmap()
	} else if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		c.IP = ap.Addr().Unmap()
	}
	return c, nil
}

// cleanHeader keeps printable ASCII only and caps the length: these values are stored and
// logged, so control characters and huge values are dropped.
func cleanHeader(v string, max int) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(v) {
		if r < 0x20 || r > 0x7e {
			continue
		}
		if b.Len() >= max {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// deviceName decodes X-Device-Name: percent-encoded UTF-8, kept only if it decodes to
// valid text; control and formatting characters (including bidi overrides that could
// disguise a name) are dropped, spaces collapsed, at most 100 characters.
func deviceName(raw string) string {
	if raw == "" || len(raw) > 1024 {
		return ""
	}
	s, err := url.PathUnescape(raw)
	if err != nil || !utf8.ValidString(s) {
		return ""
	}
	var b strings.Builder
	n := 0
	for _, r := range strings.Join(strings.Fields(s), " ") {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if n == 100 {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}
