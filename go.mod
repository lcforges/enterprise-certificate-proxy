module github.com/googleapis/enterprise-certificate-proxy

go 1.19

require (
	github.com/google/go-pkcs11 v0.2.0
	golang.org/x/crypto v0.10.0
	golang.org/x/sys v0.9.0
)

replace github.com/google/go-pkcs11 v0.2.0 => github.com/lcforges/go-pkcs11 v0.0.0-20230808214450-8e4d0532171b
