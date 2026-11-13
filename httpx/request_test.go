package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDecodeJSON(t *testing.T) {
	type body struct {
		Name string `json:"name"`
	}
	cases := map[string]struct {
		ctype, body string
		ok          bool
	}{
		"plain":            {"application/json", `{"name":"ray"}`, true},
		"charset":          {"application/json; charset=utf-8", `{"name":"ray"}`, true},
		"unknown field ok": {"application/json", `{"name":"ray","new_field":1}`, true},
		"no type":          {"", `{"name":"ray"}`, false},
		"form":             {"application/x-www-form-urlencoded", `name=ray`, false},
		"two objects":      {"application/json", `{"name":"a"}{"name":"b"}`, false},
		"trailing junk":    {"application/json", `{"name":"a"} x`, false},
		"array":            {"application/json", `[1,2]`, false},
		"too big":          {"application/json", `{"name":"` + strings.Repeat("a", MaxBodyBytes) + `"}`, false},
		"empty":            {"application/json", ``, false},
	}
	for name, c := range cases {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(c.body))
		if c.ctype != "" {
			r.Header.Set("Content-Type", c.ctype)
		}
		var b body
		err := DecodeJSON(httptest.NewRecorder(), r, &b)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v", name, err)
		}
	}
}

func TestClientFrom(t *testing.T) {
	req := func(h map[string]string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.RemoteAddr = "10.0.0.9:51234"
		for k, v := range h {
			r.Header.Set(k, v)
		}
		return r
	}

	web, err := ClientFrom(req(map[string]string{"User-Agent": "Mozilla/5.0"}))
	if err != nil || web.Type != "web" || web.IsApp() || web.IP.String() != "10.0.0.9" {
		t.Fatalf("web: %+v %v", web, err)
	}

	app, err := ClientFrom(req(map[string]string{
		"X-Client-Type": "app", "X-Client-Platform": "iPhone", "X-Device-Id": "dev-123",
		"X-App-Version": "1.4.0 (212)\x00\n", "X-Hayitone-Client-Ip": "203.0.113.7",
	}))
	if err != nil || app.Type != "ios" || app.DeviceID != "dev-123" || app.AppVersion != "1.4.0 (212)" || app.IP.String() != "203.0.113.7" {
		t.Fatalf("app: %+v %v", app, err)
	}

	for name, h := range map[string]map[string]string{
		"no platform":      {"X-Client-Type": "app", "X-Device-Id": "d"},
		"unknown platform": {"X-Client-Type": "app", "X-Client-Platform": "symbian", "X-Device-Id": "d"},
		"no device":        {"X-Client-Type": "app", "X-Client-Platform": "android"},
	} {
		if _, err := ClientFrom(req(h)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	long, _ := ClientFrom(req(map[string]string{"X-Device-Id": strings.Repeat("x", 500)}))
	if len(long.DeviceID) != 200 {
		t.Errorf("device id length %d", len(long.DeviceID))
	}
	mapped, _ := ClientFrom(req(map[string]string{"X-Hayitone-Client-Ip": "::ffff:203.0.113.7"}))
	if mapped.IP.String() != "203.0.113.7" {
		t.Errorf("IPv4-mapped address kept as %s", mapped.IP)
	}
}

func TestWriteRateLimited(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteRateLimited(rec, 1500*time.Millisecond)
	if rec.Code != 429 || rec.Header().Get("Retry-After") != "2" || !strings.Contains(rec.Body.String(), `"retry_after":2`) {
		t.Fatalf("%d %q %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body)
	}
}

func TestDeviceName(t *testing.T) {
	for in, want := range map[string]string{
		"":                                  "",
		"Pixel%208":                         "Pixel 8",
		"Ray%E2%80%99s%20iPhone":            "Ray’s iPhone",
		"%E2%80%AEenohPi":                   "enohPi", // a right-to-left override can't disguise the name
		"a%0Ab%09c":                         "a b c",  // newlines and tabs become one space
		"%ZZ":                               "",       // not percent-encoding
		"%FF%FE":                            "",       // not UTF-8
		strings.Repeat("x", 150):            strings.Repeat("x", 100),
		"   ":                               "",
		"%E5%B0%8F%E6%98%8E%E7%9A%84iPhone": "小明的iPhone",
	} {
		if got := deviceName(in); got != want {
			t.Fatalf("%q -> %q, want %q", in, got, want)
		}
	}
}
