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
		// WithDirectivesFromFile("wafreiruleset/default.conf")
		// WithDirectivesFromFile("coraza.conf").
		WithDirectivesFromFile("coreruleset/crs-setup.conf.example")
		//WithDirectivesFromFile("coreruleset/rules/*.conf")
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		panic(err)
	}
	return waf
}

func processInterrupt(resWriter *http.ResponseWriter, it *types.Interruption) {
	(*resWriter).WriteHeader(it.Status)
	log.Println("Interruption: ", it)
	(*resWriter).Write([]byte(fmt.Sprintf("Interruption: %v %v %v\n", it.Action, it.RuleID, it.Data)))
}

func handleIngress(tx types.Transaction, resWriter *http.ResponseWriter, req *http.Request) (*http.Response, error) {
	tx.ProcessConnection("localhost", 8080, "localhost", 8000)
	for k, v := range req.Header {
		tx.AddRequestHeader(k, v[0])
	}
	for k, v := range req.URL.Query() {
		tx.AddGetRequestArgument(k, v[0])
		log.Println("Request query: ", k, " = ", v[0])
	}
	tx.ProcessURI(req.URL.RawQuery, req.Method, req.Proto)
	if it := tx.ProcessRequestHeaders(); it != nil {
		processInterrupt(resWriter, it)
		return nil, errors.New("interrup in request headers") // TODO return error
	}
	body_buffer := bytes.Buffer{}
	io.Copy(&body_buffer, req.Body)
	log.Println("Request body: ", body_buffer.String())
	if it, _, err := tx.ReadRequestBodyFrom(req.Body); it != nil || err != nil {
		processInterrupt(resWriter, it)
		return nil, errors.New("interrup in processrequestbody")
	}
	tx.WriteRequestBody(body_buffer.Bytes())
	if it, err := tx.ProcessRequestBody(); it != nil || err != nil {
		processInterrupt(resWriter, it)
		return nil, errors.New("interrup in processrequestbody")
	}

	client := &http.Client{}
	req.RequestURI = ""
	req.URL.Scheme = "http"
	req.URL.Host = "localhost:8000"
	req.URL.RawPath = req.URL.Path
	req.URL.RawQuery = req.URL.Query().Encode()
	req.Body = io.NopCloser(bytes.NewReader(body_buffer.Bytes()))
	if req.Header.Get("Referer") == "http://localhost:8080" {
		println("Setting referer")
		req.Header.Set("Referer", "http://localhost:8000")
	}
	res, err := client.Do(req)
	if err != nil {
		log.Println("Error inside handle Ingress: ", err)
		return nil, err
	}
	log.Println("Backend response: ", res.StatusCode)
	return res, nil
}

func handleEgress(tx types.Transaction, resWriter *http.ResponseWriter, backend_res *http.Response) error {
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
	log.Printf("Request: %v %v\n", req.Method, req.URL.Path)
	tx := (*waf).NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()
	res, err := handleIngress(tx, &resWriter, req)
	if err != nil {
		log.Printf("Ingress error: %v\n", err)
		return
	}
	log.Printf("Response: %v\n", res.StatusCode)
	if err := handleEgress(tx, &resWriter, res); err != nil {
		log.Printf("Egress error: %v\n", err)
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
