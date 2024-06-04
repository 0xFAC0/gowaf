# Coraza WAF PoC

## Usage

```
git clone https://github.com/0xFAC0/gowaf
cd gowaf
go run .
```

You can access test the waf by accessing 8080 and the web server at 8000
it is recommanded to use the DVWA docker

```
docker run --rm -it -p 8000:80 vulnerables/web-dvwa
```