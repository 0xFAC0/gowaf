package main

import (
	"bytes"
	"errors"
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

func processInterrupt(resWriter *http.ResponseWriter, it *types.Interruption) {
	(*resWriter).WriteHeader(it.Status)
	fmt.Fprintf((*resWriter), "Interruption: %v\n", it)
	fmt.Println("Interruption: ", it)
	(*resWriter).Write([]byte(it.Data))
}

func handleIngress(resWriter *http.ResponseWriter, req *http.Request, waf *coraza.WAF) (*http.Response, error) {
	tx := (*waf).NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()
	tx.ProcessConnection("localhost", 8080, "localhost", 8000)
	// TODO preserve referer
	for k, v := range req.Header {
		tx.AddRequestHeader(k, v[0])
	}
	// tx.AddRequestHeader("Host", req.Host)
	// tx.AddRequestHeader("User-Agent", req.UserAgent())
	// tx.AddRequestHeader("Content-Type", req.Header.Get("Content-Type"))
	tx.ProcessURI(req.URL.RawQuery, req.Method, req.Proto)
	if it := tx.ProcessRequestHeaders(); it != nil {
		processInterrupt(resWriter, it)
		return nil, errors.New("interrup in request headers") // TODO return error
	}
	var body_buffer bytes.Buffer
	if req.Body != nil {
		body_buffer = bytes.Buffer{}
		io.Copy(&body_buffer, req.Body)
		tx.WriteRequestBody(body_buffer.Bytes())
		if it, err := tx.ProcessRequestBody(); it != nil || err != nil {
			processInterrupt(resWriter, it)
			return nil, errors.New("interrup in processrequestbody")
		}
	}

	client := &http.Client{}
	newReq, _ := http.NewRequest(req.Method, "http://localhost:8000"+req.URL.Path, req.Body)
	newReq.Header = req.Header
	res, err := client.Do(newReq)
	if err != nil {
		fmt.Println("Error inside handle Ingress: ", err)
		return nil, err
	}
	fmt.Println("Backend response: ", res.StatusCode)
	return res, nil
}

func handleEgress(resWriter *http.ResponseWriter, backend_res *http.Response, waf *coraza.WAF) error {
	tx := (*waf).NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()
	tx.ProcessConnection("localhost", 8000, "localhost", 8080)
	respBody := new(bytes.Buffer)
	io.Copy(respBody, backend_res.Body)

	if it, _, err := tx.WriteResponseBody(respBody.Bytes()); it != nil || err != nil {
		processInterrupt(resWriter, it)
		return errors.New("interrup in writeresponsebody")
	}
	if it, err := tx.ProcessResponseBody(); it != nil || err != nil {
		processInterrupt(resWriter, it)
		return errors.New("interrup in processresponsebody")
	}
	for k, v := range backend_res.Header {
		(*resWriter).Header().Set(k, v[0])
	}
	io.Copy(*resWriter, respBody)
	return nil
}

func handler(resWriter http.ResponseWriter, req *http.Request, waf *coraza.WAF) {
	fmt.Printf("Request: %v %v\n", req.Method, req.URL.Path)
	res, err := handleIngress(&resWriter, req, waf)
	if err != nil {
		fmt.Printf("Ingress error: %v\n", err)
		return
	}
	fmt.Printf("Response: %v\n", res.StatusCode)
	if err := handleEgress(&resWriter, res, waf); err != nil {
		fmt.Printf("Egress error: %v\n", err)
		return
	}
}

func main() {
	waf := initCoraza()
	println("Coraza Waf initialized")

	log.Fatal(http.ListenAndServe(":8080", http.HandlerFunc(func(resWriter http.ResponseWriter, req *http.Request) {
		handler(resWriter, req, &waf)
	})))
}
