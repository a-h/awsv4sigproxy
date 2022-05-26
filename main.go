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
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
)

var remoteFlag = flag.String("remote", "", "The base URL of the remote API to call, e.g. https://ej9a7qm7ye.execute-api.eu-west-1.amazonaws.com")
var localFlag = flag.String("local", "localhost:6666", "The local address to listen on.")
var serviceFlag = flag.String("service", "execute-api", "The service (execute-api for API Gateway, lambda for Lambda function URLs).")

func main() {
	flag.Parse()
	if *remoteFlag == "" {
		flag.PrintDefaults()
		os.Exit(1)
		return
	}
	if err := run(*localFlag, *remoteFlag, *serviceFlag); err != nil {
		log.Fatal(err)
	}
}

func run(local, remote string, service string) error {
	p, messages, errors, err := NewProxy(remote, service)
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
	log.Printf("Proxying from %v to %v\n", local, remote)
	return http.ListenAndServe(local, p)
}

func NewProxy(baseURL string, service string) (p http.Handler, messages chan string, errors chan error, err error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, nil, nil, err
	}
	signer, err := NewSigner(u, service)
	if err != nil {
		return nil, nil, nil, err
	}
	messages = signer.Messages
	errors = signer.Errors

	return signer, messages, errors, nil
}

type Signer struct {
	baseURL  *url.URL
	signer   *v4.Signer
	cfg      aws.Config
	region   string
	now      func() time.Time
	service  string
	Messages chan string
	Errors   chan error
}

func NewSigner(u *url.URL, service string) (c Signer, err error) {
	c.cfg, err = config.LoadDefaultConfig(context.Background())
	if err != nil {
		return
	}
	c.baseURL = u
	c.region = c.cfg.Region
	c.signer = v4.NewSigner()
	c.now = time.Now
	c.service = service
	c.Errors = make(chan error)
	c.Messages = make(chan string)
	return
}

const emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func (c Signer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// If there is no payload, default to an empty buffer and the empty hash.
	hash := emptyHash
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			c.Errors <- fmt.Errorf("v4sigproxy: failed to read body: %w", err)
			return
		}
		// Hasher to compute body hash.
		h := sha256.Sum256(body)
		hash = hex.EncodeToString(h[:])
	}

	before := r.URL.String()
	r.URL.Scheme = c.baseURL.Scheme
	r.URL.Host = c.baseURL.Host
	r.Host = c.baseURL.Host
	after := r.URL.String()
	c.Messages <- fmt.Sprintf("%v -> %v with body %v", before, after, hash)

	req, err := http.NewRequest(r.Method, after, bytes.NewReader(body))
	if err != nil {
		c.Errors <- fmt.Errorf("v4sigproxy: failed to create outbound request: %w", err)
		return
	}
	// Get signing credentials.
	creds, err := c.cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		c.Errors <- fmt.Errorf("v4sigproxy: failed to retrieve creds: %w", err)
		return
	}
	err = c.signer.SignHTTP(context.Background(), creds, req, hash, c.service, c.region, c.now())
	if err != nil {
		c.Errors <- fmt.Errorf("v4sigproxy: failed to sign request: %w", err)
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.Errors <- fmt.Errorf("v4sigproxy: failed to make outbound request: %w", err)
		return
	}

	// Return response.
	// Copy headers over.
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	// Copy body.
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		c.Errors <- fmt.Errorf("v4sigproxy: failed to copy bound from remote to client: %w", err)
		return
	}
	return
}
