package referrer_test

import (
	"log"
	"net/http"

	"github.com/saihon/referrer"
)

func Example() {
	r := referrer.New()
	r.SetPolicy(referrer.POLICY_ORIGIN_WHEN_CROSS_ORIGIN)

	fromURL := "http://example.com/from"
	toURL := "http://example.com/to"

	req, err := http.NewRequest(`GET`, toURL, nil)
	if err != nil {
		log.Fatal(err)
	}

	referer, ok := r.Make(fromURL, toURL)
	// set referer
	if ok {
		req.Header.Set("Referer", referer)
	}

	http.DefaultClient.Do(req)
}

// This example shows how to use SetCustomPolicy
func ExamplePolicyFunc() {
	r := referrer.New()

	const CUSTOM_POLICY referrer.Policy = 8

	var customPolicyFunc = func(fromURL, toURL string) (referer string) {
		from, err := referrer.Parse(fromURL)
		if err != nil {
			return
		}

		to, err := referrer.Parse(toURL)
		if err != nil {
			return
		}

		if from.TLS && to.TLS {
			return from.Origin
		}
		return
	}

	r.SetCustomPolicy(CUSTOM_POLICY, customPolicyFunc)

	r.SetPolicy(CUSTOM_POLICY)
}
