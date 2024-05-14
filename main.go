package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/corazawaf/coraza/v3"
	types "github.com/corazawaf/coraza/v3/types"
)

func initCoraza() coraza.WAF {
	cfg := coraza.NewWAFConfig().
		WithDirectivesFromFile("coraza.conf").
		WithDirectivesFromFile("wafreiruleset/evilurl.conf").
		WithDirectivesFromFile("coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("coreruleset/rules/*.conf")
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		panic(err)
	}
	return waf
}

func processInterrupt(resWriter http.ResponseWriter, it *types.Interruption) {
	resWriter.WriteHeader(it.Status)
	fmt.Fprintf(resWriter, "Interruption: %v\n", it)
	resWriter.Write([]byte(it.Data))
}

func handler(resWriter http.ResponseWriter, req *http.Request, waf *coraza.WAF) {
	tx := (*waf).NewTransaction()
	tx.ProcessConnection("localhost", 8080, "localhost", 8000)
	tx.AddRequestHeader("Host", req.Host)
	tx.AddRequestHeader("User-Agent", req.UserAgent())
	tx.AddRequestHeader("Content-Type", req.Header.Get("Content-Type"))
	tx.ProcessURI(req.URL.RawQuery, req.Method, req.Proto)
	if it := tx.ProcessRequestHeaders(); it != nil {
		processInterrupt(resWriter, it)
		return
	}
	if req.Body != nil {
		body_buffer := new(bytes.Buffer)
		io.Copy(body_buffer, req.Body)
		tx.WriteRequestBody(body_buffer.Bytes())
		if it, err := tx.ProcessRequestBody(); it != nil || err != nil {
			processInterrupt(resWriter, it)
			return
		}
	}
	tx.ProcessURI(req.URL.RawQuery, req.Method, req.Proto)
	resp, _ := http.Get("http://localhost:8000" + req.URL.Path)
	fmt.Printf("Response: %v\n", resp)
	// Handle res
	tx.AddResponseHeader("Content-Type", resp.Header.Get("Content-Type"))
	respBody := new(bytes.Buffer)
	io.Copy(respBody, resp.Body)

	if it, _, err := tx.WriteResponseBody(respBody.Bytes()); it != nil || err != nil {
		processInterrupt(resWriter, it)
		return
	}
	if it, err := tx.ProcessResponseBody(); it != nil || err != nil {
		processInterrupt(resWriter, it)
		return
	}
	// Res to client
	// fmt.Printf("Response: %v\n", respBody)
	resWriter.WriteHeader(resp.StatusCode)
	resWriter.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	io.Copy(resWriter, respBody)
}

func main() {
	waf := initCoraza()
	println("Coraza Waf initialized")

	log.Fatal(http.ListenAndServe(":8080", http.HandlerFunc(func(resWriter http.ResponseWriter, req *http.Request) {
		handler(resWriter, req, &waf)
	})))
}
