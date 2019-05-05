package referrer

import (
	"errors"
	"net/url"
	"strings"
)

//
// https://www.w3.org/TR/referrer-policy/
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
//

type Policy uint

const (
	// POLICY_NO_REFERRER (- no-referrer)
	POLICY_NO_REFERRER Policy = iota

	// POLICY_NO_REFERRER_WHEN_DOWNGRADE (- no-referrer-when-downgrade)
	POLICY_NO_REFERRER_WHEN_DOWNGRADE

	// POLICY_SAME_ORIGIN (- same-origin)
	POLICY_SAME_ORIGIN

	// POLICY_ORIGIN (- origin)
	POLICY_ORIGIN

	// POLICY_STRICT_ORIGIN (- strict-origin)
	POLICY_STRICT_ORIGIN

	// POLICY_ORIGIN_WHEN_CROSS_ORIGIN (- origin-when-cross-origin)
	POLICY_ORIGIN_WHEN_CROSS_ORIGIN

	// POLICY_STRICT_ORIGIN_WHEN_CROSS_ORIGIN (- strict-origin-when-cross-origin)
	POLICY_STRICT_ORIGIN_WHEN_CROSS_ORIGIN

	// POLICY_UNSAFE_URL (- unsafe-url)
	POLICY_UNSAFE_URL
)

type PolicyFunc func(fromURL string, toURL string) string

var (
	LocalScheme = []string{"about", "blob", "data", "filesystem"}
)

func isLocalScheme(rawurl string) bool {
	for _, v := range LocalScheme {
		if strings.HasPrefix(rawurl, v) {
			return true
		}
	}
	return false
}

type URL struct {
	*url.URL
	Origin      string
	TLS         bool
	LocalScheme bool
}

// Parse given URL string to *URL
func Parse(rawurl string) (*URL, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	if !u.IsAbs() {
		return nil, errors.New("not absolute URL")
	}

	// url.UserInfo (username:password) set nil
	u.User = nil
	// delete fragment
	u.Fragment = ""

	parsed := &URL{
		URL: u,
	}

	if strings.HasPrefix(u.Scheme, "https") || strings.HasPrefix(u.Scheme, "ftps") {
		parsed.TLS = true
	}

	// Delete port number
	index := strings.Index(u.Host, ":")
	if index != -1 {
		u.Host = u.Host[:index]
	}

	parsed.LocalScheme = isLocalScheme(u.Scheme)
	parsed.Origin = u.Scheme + "://" + u.Host + "/"

	return parsed, nil
}

type Referrer struct {
	policy Policy
	m      map[Policy]PolicyFunc
}

// New default policy is POLICY_NO_REFERRER_WHEN_DOWNGRADE if no policy is changed.
func New() *Referrer {
	return &Referrer{
		policy: POLICY_NO_REFERRER_WHEN_DOWNGRADE,
		m: map[Policy]PolicyFunc{
			POLICY_NO_REFERRER:                     PolicyFuncNoReferrer,
			POLICY_NO_REFERRER_WHEN_DOWNGRADE:      PolicyFuncNoReferrerWhenDownGrade,
			POLICY_SAME_ORIGIN:                     PolicyFuncSameOrigin,
			POLICY_ORIGIN:                          PolicyFuncOrigin,
			POLICY_STRICT_ORIGIN:                   PolicyFuncStrictOrigin,
			POLICY_ORIGIN_WHEN_CROSS_ORIGIN:        PolicyFuncOriginWhenCrossOrigin,
			POLICY_STRICT_ORIGIN_WHEN_CROSS_ORIGIN: PolicyFuncStrictOriginWhenCrossOrigin,
			POLICY_UNSAFE_URL:                      PolicyFuncUnsafeURL,
		},
	}
}

// SetCustomPolicy is set any referrer-policy and that function
func (r *Referrer) SetCustomPolicy(policy Policy, policyFunc PolicyFunc) {
	r.m[policy] = policyFunc
}

// SetPolicy is change to the given policy
func (r *Referrer) SetPolicy(policy Policy) {
	r.policy = policy
}

// GetPolicy returns the currently set policy
func (r *Referrer) GetPolicy() Policy {
	return r.policy
}

// Make is making referrer value based on a policy
func (r *Referrer) Make(fromURL, toURL string) (referer string, ok bool) {
	if len(fromURL) == 0 {
		return
	}

	if isLocalScheme(fromURL) {
		return
	}

	if fn, ok := r.m[r.policy]; ok {
		referer := fn(fromURL, toURL)
		return referer, referer != ""
	}

	return
}

// PolicyFuncNoReferrer
var PolicyFuncNoReferrer PolicyFunc = func(fromURL, toURL string) string {
	return ""
}

// PolicyFuncUnsafeURL
var PolicyFuncUnsafeURL PolicyFunc = func(fromURL, toURL string) string {
	u, err := Parse(fromURL)
	if err != nil {
		return ""
	}
	return u.String()
}

// PolicyFuncNoReferrerWhenDownGrade
var PolicyFuncNoReferrerWhenDownGrade PolicyFunc = func(fromURL, toURL string) (referer string) {
	from, err := Parse(fromURL)
	if err != nil {
		return
	}

	to, err := Parse(toURL)
	if err != nil {
		return
	}

	// non-potentially trustworthy URLs
	if from.TLS && !to.TLS {
		return
	}
	// return full URL, requests from a TLS-protected environment
	return from.String()
}

// PolicyFuncSameOrigin
var PolicyFuncSameOrigin PolicyFunc = func(fromURL, toURL string) (referer string) {
	from, err := Parse(fromURL)
	if err != nil {
		return
	}

	to, err := Parse(toURL)
	if err != nil {
		return
	}

	// return full URL when same-origin requests
	if to.Origin == from.Origin {
		return from.String()
	}
	return
}

// PolicyFuncOrigin
var PolicyFuncOrigin PolicyFunc = func(fromURL, toURL string) (referer string) {
	from, err := Parse(fromURL)
	if err != nil {
		return
	}
	// always return the origin
	return from.Origin
}

// PolicyFuncStrictOrigin
var PolicyFuncStrictOrigin PolicyFunc = func(fromURL, toURL string) (referer string) {
	from, err := Parse(fromURL)
	if err != nil {
		return
	}

	to, err := Parse(toURL)
	if err != nil {
		return
	}

	// from non-TLS-protected environment
	if from.TLS && !to.TLS {
		return
	}
	// from a TLS-protected environment to a potentially trustworthy URL
	return from.Origin
}

// PolicyFuncOriginWhenCrossOrigin
var PolicyFuncOriginWhenCrossOrigin PolicyFunc = func(fromURL, toURL string) (referer string) {
	from, err := Parse(fromURL)
	if err != nil {
		return
	}

	to, err := Parse(toURL)
	if err != nil {
		return
	}

	// same-origin requests
	if from.Origin == to.Origin {
		return from.String()
	}
	// cross-origin requests
	return from.Origin
}

// PolicyFuncStrictOriginWhenCrossOrigin
var PolicyFuncStrictOriginWhenCrossOrigin PolicyFunc = func(fromURL, toURL string) (referer string) {
	from, err := Parse(fromURL)
	if err != nil {
		return
	}

	to, err := Parse(toURL)
	if err != nil {
		return
	}

	// from TLS-protected to non-potentially trustworthy URLs
	if from.TLS && !to.TLS {
		return
	}

	// return full URL, if same-origin requests
	if from.Origin == to.Origin {
		return from.String()
	}

	// return origin
	// from a TLS-protected environment to a potentially trustworthy URL and
	// from non-TLS-protected environment to any origin
	return from.Origin
}
