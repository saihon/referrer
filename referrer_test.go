package referrer

import (
	"reflect"
	"testing"
)

func TestPolicyMap(t *testing.T) {
	r := New()
	for k, v := range r.m {
		switch k {
		case POLICY_NO_REFERRER:
			actual := reflect.ValueOf(v).Pointer()
			expect := reflect.ValueOf(PolicyFuncNoReferrer).Pointer()
			if actual != expect {
				t.Errorf("\nPOLICY_NO_REFERER is should be PolicyFuncNoReferer\n")
			}

		case POLICY_NO_REFERRER_WHEN_DOWNGRADE:
			actual := reflect.ValueOf(v).Pointer()
			expect := reflect.ValueOf(PolicyFuncNoReferrerWhenDownGrade).Pointer()
			if actual != expect {
				t.Errorf("\nPOLICY_NO_REFERER_WHEN_DOWNGRADE is should be PolicyFuncNoRefererWhenDownGrade\n")
			}

		case POLICY_SAME_ORIGIN:
			actual := reflect.ValueOf(v).Pointer()
			expect := reflect.ValueOf(PolicyFuncSameOrigin).Pointer()
			if actual != expect {
				t.Errorf("\nPOLICY_SAME_ORIGIN is should be PolicyFuncSameOrigin\n")
			}

		case POLICY_ORIGIN:
			actual := reflect.ValueOf(v).Pointer()
			expect := reflect.ValueOf(PolicyFuncOrigin).Pointer()
			if actual != expect {
				t.Errorf("\nPOLICY_ORIGIN is should be PolicyFuncOrigin\n")
			}

		case POLICY_STRICT_ORIGIN:
			actual := reflect.ValueOf(v).Pointer()
			expect := reflect.ValueOf(PolicyFuncStrictOrigin).Pointer()
			if actual != expect {
				t.Errorf("\nPOLICY_STRICT_ORIGIN is should be PolicyFuncStrictOrigin\n")
			}

		case POLICY_ORIGIN_WHEN_CROSS_ORIGIN:
			actual := reflect.ValueOf(v).Pointer()
			expect := reflect.ValueOf(PolicyFuncOriginWhenCrossOrigin).Pointer()
			if actual != expect {
				t.Errorf("\nPOLICY_ORIGIN_WHEN_CROSS_ORIGIN is should be PolicyFuncOriginWhenCrossOrigin\n")
			}

		case POLICY_STRICT_ORIGIN_WHEN_CROSS_ORIGIN:
			actual := reflect.ValueOf(v).Pointer()
			expect := reflect.ValueOf(PolicyFuncStrictOriginWhenCrossOrigin).Pointer()
			if actual != expect {
				t.Errorf("\nPOLICY_STRICT_ORIGIN_WHEN_CROSS_ORIGIN is should be PolicyFuncStrictOriginWhenCrossOrigin\n")
			}

		case POLICY_UNSAFE_URL:
			actual := reflect.ValueOf(v).Pointer()
			expect := reflect.ValueOf(PolicyFuncUnsafeURL).Pointer()
			if actual != expect {
				t.Errorf("\nPOLICY_UNSAFE_URL is should be PolicyFuncUnsafeURL\n")
			}
		}
	}
}

func TestParse(t *testing.T) {
	type Expect struct {
		rawurl      string
		origin      string
		tls         bool
		localscheme bool
	}

	data := []struct {
		rawurl     string
		expect     Expect
		errorOccur bool
	}{
		{ // delete user info
			"http://username:password@example.com/",
			Expect{
				rawurl:      "http://example.com/",
				origin:      "http://example.com/",
				tls:         false,
				localscheme: false,
			},
			false},
		{ // TLS https
			"https://example.com/index.php",
			Expect{
				rawurl:      "https://example.com/index.php",
				origin:      "https://example.com/",
				tls:         true,
				localscheme: false,
			},
			false},
		{ // TLS ftps
			"ftps://example.com/file.json",
			Expect{
				rawurl:      "ftps://example.com/file.json",
				origin:      "ftps://example.com/",
				tls:         true,
				localscheme: false,
			},
			false},
		{ // domain
			"http://www.example.com/",
			Expect{
				rawurl:      "http://www.example.com/",
				origin:      "http://www.example.com/",
				tls:         false,
				localscheme: false,
			},
			false},
		{ // delete port number
			"http://example.com:80/",
			Expect{
				rawurl:      "http://example.com/",
				origin:      "http://example.com/",
				tls:         false,
				localscheme: false,
			},
			false},
		{ // delete fragment
			"http://example.com/#fragment",
			Expect{
				rawurl:      "http://example.com/",
				origin:      "http://example.com/",
				tls:         false,
				localscheme: false,
			},
			false},
		{ // local scheme
			"data://example.com/#fragment",
			Expect{
				rawurl:      "data://example.com/",
				origin:      "data://example.com/",
				tls:         false,
				localscheme: true,
			},
			false},
		{ // an error should occur
			"example.com", Expect{}, true},
	}

	for i, v := range data {
		u, err := Parse(v.rawurl)
		if v.errorOccur {
			if err == nil {
				t.Errorf("\n%d: an error should occur\n", i)
			}
		} else if err != nil {
			t.Errorf("\n%d: must be not an error: %s\n", i, err)
		} else {
			if u.String() != v.expect.rawurl {
				t.Errorf("\n%d: got : %s, want: %s\n", i, u.String(), v.expect.rawurl)
			}
			if u.Origin != v.expect.origin {
				t.Errorf("\n%d origin: got : %s, want: %s\n", i, u.Origin, v.expect.origin)
			}
			if u.LocalScheme != v.expect.localscheme {
				t.Errorf("\n%d local scheme: got : %v, want: %v\n", i, u.LocalScheme, v.expect.localscheme)
			}
			if u.TLS != v.expect.tls {
				t.Errorf("\n%d TLS: got : %v, want: %v\n", i, u.TLS, v.expect.tls)
			}
		}
	}
}

func TestNoReferrer(t *testing.T) {
	referer := PolicyFuncNoReferrer("http://example.com/from", "http://example.com/to")
	if referer != "" {
		t.Errorf("\nreferrer value is must be empty\n")
	}
}

func TestPolicyFuncUnsafeURL(t *testing.T) {
	data := []struct {
		toURL   string
		fromURL string
	}{
		{
			fromURL: "http://example.com/index.php",
			toURL:   "http://example.com/index2.php"},
		{
			fromURL: "http://example.com/index.php",
			toURL:   "http://www.example.com/index.php"},
		{
			fromURL: "http://godoc.org/index.php",
			toURL:   "http://example.com/index.php"},
	}

	for i, v := range data {
		actual := PolicyFuncUnsafeURL(v.fromURL, v.toURL)
		if actual != v.fromURL {
			t.Errorf("\n%d: got : %s, want: %s\n", i, actual, v.fromURL)
		}
	}
}

func TestPolicyFuncNoRefererWhenDownGrade(t *testing.T) {
	data := []struct {
		expect  string
		fromURL string
		toURL   string
	}{
		{ // same security level
			expect:  "http://example.com/from",
			fromURL: "http://example.com/from",
			toURL:   "http://example.com/to"},
		{ // same security level
			expect:  "https://example.com/from",
			fromURL: "https://example.com/from",
			toURL:   "https://example.com/to"},
		{ // to a less secure destination
			expect:  "",
			fromURL: "https://example.com/from",
			toURL:   "http://example.com/to"},
	}

	for i, v := range data {
		actual := PolicyFuncNoReferrerWhenDownGrade(v.fromURL, v.toURL)
		if actual != v.expect {
			t.Errorf("\n%d: got : %s, want: %s\n", i, actual, v.expect)
		}
	}
}

func TestPolicyFuncSameOrigin(t *testing.T) {
	data := []struct {
		expect  string
		toURL   string
		fromURL string
	}{
		{ // same origin
			expect:  "http://example.com/from",
			fromURL: "http://example.com/from",
			toURL:   "http://example.com/to"},
		{ // Different origin
			expect:  "",
			fromURL: "https://example.com/from",
			toURL:   "http://example.com/to"},
		{
			expect:  "",
			fromURL: "http://example.com/from",
			toURL:   "http://www.example.com/to"},
		{
			expect:  "",
			fromURL: "http://godoc.org/from",
			toURL:   "http://example.com/to"},
	}

	for i, v := range data {
		actual := PolicyFuncSameOrigin(v.fromURL, v.toURL)
		if actual != v.expect {
			t.Errorf("\n%d: got : %s, want: %s\n", i, actual, v.expect)
			break
		}
	}
}

func TestPolicyFuncOrigin(t *testing.T) {
	data := []struct {
		expect  string
		toURL   string
		fromURL string
	}{
		{
			expect:  "http://example.com/",
			fromURL: "http://example.com/from",
			toURL:   "http://example.com/to"},
		{
			expect:  "http://example.com/",
			fromURL: "http://example.com/from",
			toURL:   "http://www.example.com/to"},
		{
			expect:  "http://godoc.org/",
			fromURL: "http://godoc.org/from",
			toURL:   "http://www.example.com/to"},
	}

	for i, v := range data {
		actual := PolicyFuncOrigin(v.fromURL, v.toURL)
		if actual != v.expect {
			t.Errorf("\n%d: got : %s, want: %s\n", i, actual, v.expect)
			break
		}
	}
}

func TestPolicyFuncStrictOrigin(t *testing.T) {
	data := []struct {
		expect  string
		toURL   string
		fromURL string
	}{
		{
			expect:  "http://example.com/",
			fromURL: "http://example.com/from",
			toURL:   "http://example.com/to"},
		{
			expect:  "http://example.com/",
			fromURL: "http://example.com/from",
			toURL:   "https://example.com/to"},
		{
			expect:  "https://example.com/",
			fromURL: "https://example.com/from",
			toURL:   "https://example.com/to"},
		{
			expect:  "http://example.com/",
			fromURL: "http://example.com/from",
			toURL:   "http://www.example.com/to"},
		{
			expect:  "https://example.com/",
			fromURL: "https://example.com/from",
			toURL:   "https://godoc.org/to"},
		{
			expect:  "",
			fromURL: "https://example.com/from",
			toURL:   "http://example.com/to"},
		{
			expect:  "",
			fromURL: "https://example.com/from",
			toURL:   "http://godoc.org/to"},
	}

	for i, v := range data {
		actual := PolicyFuncStrictOrigin(v.fromURL, v.toURL)
		if actual != v.expect {
			t.Errorf("\n%d: got : %s, want: %s\n", i, actual, v.expect)
			break
		}
	}
}

func TestPolicyFuncOriginWhenCrossOrigin(t *testing.T) {
	data := []struct {
		expect  string
		toURL   string
		fromURL string
	}{
		{ // same origin
			expect:  "http://example.com/from",
			fromURL: "http://example.com/from",
			toURL:   "http://example.com/to"},
		{ // same origin
			expect:  "https://example.com/from",
			fromURL: "https://example.com/from",
			toURL:   "https://example.com/to"},
		{ // Different origin
			expect:  "http://example.com/",
			fromURL: "http://example.com/from",
			toURL:   "https://example.com/to"},
		{
			expect:  "https://example.com/",
			fromURL: "https://example.com/from",
			toURL:   "http://example.com/to"},
		{
			expect:  "http://example.com/",
			fromURL: "http://example.com/from",
			toURL:   "http://www.example.com/to"},
		{
			expect:  "http://example.com/",
			fromURL: "http://example.com/from",
			toURL:   "http://godoc.org/to"},
	}

	for i, v := range data {
		actual := PolicyFuncOriginWhenCrossOrigin(v.fromURL, v.toURL)
		if actual != v.expect {
			t.Errorf("\n%d: got : %s, want: %s\n", i, actual, v.expect)
			break
		}
	}
}

func TestPolicyFuncStrictOriginWhenCrossOrigin(t *testing.T) {
	data := []struct {
		expect  string
		toURL   string
		fromURL string
	}{
		{ // Same origin and same secure level
			expect:  "https://example.com/from",
			fromURL: "https://example.com/from",
			toURL:   "https://example.com/to"},
		{ // Different origin and same secure level
			expect:  "https://example.com/",
			fromURL: "https://example.com/from",
			toURL:   "https://golang.org/to"},
		{ // Different secure level
			expect:  "",
			fromURL: "https://example.com/from",
			toURL:   "http://example.com/to"},
		{ // Different secure level
			expect:  "http://example.com/",
			fromURL: "http://example.com/from",
			toURL:   "https://example.com/to"},
		{ // Different origin same secure level
			expect:  "http://example.com/",
			fromURL: "http://example.com/from",
			toURL:   "http://www.example.com/to"},
		{ // Different secure level, down grade
			expect:  "",
			fromURL: "https://example.com/from",
			toURL:   "http://example.com/to"},
	}

	for i, v := range data {
		actual := PolicyFuncStrictOriginWhenCrossOrigin(v.fromURL, v.toURL)
		if actual != v.expect {
			t.Errorf("\n%d: got : %s, want: %s\n", i, actual, v.expect)
		}
	}
}
