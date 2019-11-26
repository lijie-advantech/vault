package api

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
)

func httpDo(method string, url string, body []byte, tokenHeader string, token string) (*http.Response, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		fmt.Println(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if tokenHeader == "Authorization" {
		req.Header.Set(tokenHeader, "Bearer "+token)
	} else if tokenHeader == "X-Vault-Token" {
		req.Header.Set(tokenHeader, token)
	}

	return client.Do(req)
}
