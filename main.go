package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
)

var remoteFlag = flag.String("remote", "", "The base URL of the remote API to call, e.g. https://ej9a7qm7ye.execute-api.eu-west-1.amazonaws.com")
var localFlag = flag.String("local", "localhost:6666", "The local address to listen on.")

func main() {
	flag.Parse()
	if *remoteFlag == "" {
		flag.PrintDefaults()
		os.Exit(1)
		return
	}
	if err := run(*localFlag, *remoteFlag); err != nil {
		log.Fatal(err)
	}
}

func run(local, remote string) error {
	p, messages, errors, err := NewProxy(remote)
	if err != nil {
		return err
	}
	go func() {
		for {
			select {
			case err := <-errors:
				log.Printf("error: %v\n", err)
			case msg := <-messages:
				log.Printf("message: %v\n", msg)
			}
		}
	}()
	log.Printf("About to listen on %v\n", local)
	return http.ListenAndServe(local, p)
}

func NewProxy(baseURL string) (p http.Handler, messages chan string, errors chan error, err error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, nil, nil, err
	}
	signer, err := NewSigner(u)
	if err != nil {
		return nil, nil, nil, err
	}
	messages = signer.Messages
	errors = signer.Errors

	pp := httputil.NewSingleHostReverseProxy(u)
	pp.Director = signer.Sign
	return pp, messages, errors, nil
}

type Signer struct {
	baseURL  *url.URL
	signer   *v4.Signer
	cfg      aws.Config
	region   string
	now      func() time.Time
	Messages chan string
	Errors   chan error
}

func NewSigner(u *url.URL) (c Signer, err error) {
	c.cfg, err = config.LoadDefaultConfig(context.Background())
	if err != nil {
		return
	}
	c.baseURL = u
	c.region = c.cfg.Region
	c.signer = v4.NewSigner()
	c.now = time.Now
	c.Errors = make(chan error)
	c.Messages = make(chan string)
	return
}

const emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func (c Signer) Sign(r *http.Request) {
	// If there is no payload, default to an empty buffer and the empty hash.
	hash := emptyHash
	body := new(bytes.Buffer)
	if r.Body != nil {
		// Hasher to compute body hash.
		bodyHasher := sha256.New()

		// Calculate the hash and copy it to the buffer.
		_, err := io.Copy(io.MultiWriter(bodyHasher, body), r.Body)
		if err != nil {
			c.Errors <- fmt.Errorf("v4sigproxy: failed to hash request: %w", err)
			return
		}
		hash = hex.EncodeToString(bodyHasher.Sum(nil))
	}

	before := r.URL.String()
	r.URL.Scheme = c.baseURL.Scheme
	r.URL.Host = c.baseURL.Host
	r.Host = c.baseURL.Host
	after := r.URL.String()
	c.Messages <- fmt.Sprintf("%v -> %v with body %v", before, after, hash)

	// Get signing credentials.
	creds, err := c.cfg.Credentials.Retrieve(r.Context())
	if err != nil {
		c.Errors <- fmt.Errorf("v4sigproxy: failed to retrieve creds: %w", err)
		return
	}

	// Sign the request.
	r.Body = io.NopCloser(bytes.NewReader(body.Bytes()))
	err = c.signer.SignHTTP(r.Context(), creds, r, hash, "execute-api", c.region, c.now())
	if err != nil {
		c.Errors <- fmt.Errorf("v4sigproxy: failed to sign request: %w", err)
		return
	}
	return
}
