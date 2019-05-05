## referrer

[![Build Status](https://travis-ci.org/saihon/referrer.svg?branch=master)](https://travis-ci.org/saihon/referrer) [![GoDoc](https://godoc.org/github.com/saihon/referrer?status.svg)](https://godoc.org/github.com/saihon/referrer)

<br/>
<br/>

## example

```go
package main

import (
	"log"
	"net/http"

	"github.com/saihon/referrer"
)

func main() {
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

```

<br/>
<br/>
