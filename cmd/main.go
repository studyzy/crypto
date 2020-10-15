package main

import (
	"encoding/pem"
	"fmt"
	"runtime/debug"

	"github.com/studyzy/crypto/ecdsa"
	"github.com/studyzy/crypto/elliptic"
	"github.com/studyzy/crypto/sha256"
	"github.com/studyzy/crypto/x509"
)

func main() {

	testEcdsa()
	return
	k, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		fmt.Print(err)
		debug.PrintStack()
	}
	fmt.Printf("%#v\n", k)
	pubKey := k.PublicKey
	fmt.Printf("%T %v\n", pubKey, pubKey)
	a, err := x509.MarshalPKIXPublicKey(&pubKey)
	if err != nil {
		fmt.Print(err)
	}
	fmt.Printf("%v", a)
	certStr := `-----BEGIN CERTIFICATE-----
MIICPjCCAeSgAwIBAgIRAIMBGjwXo+nfsd5AZMgBlmkwCgYIKoEcz1UBg3UwaTEL
MAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBG
cmFuY2lzY28xFDASBgNVBAoTC2V4YW1wbGUuY29tMRcwFQYDVQQDEw5jYS5leGFt
cGxlLmNvbTAeFw0yMDEwMTAxNjU5MDBaFw0zMDEwMDgxNjU5MDBaMGkxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNp
c2NvMRQwEgYDVQQKEwtleGFtcGxlLmNvbTEXMBUGA1UEAxMOY2EuZXhhbXBsZS5j
b20wWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAARGTp0cib0YnTtpo2CQXJj2Oe55
4G0p3/s0ZS57Xph4Y0Jo1KBSkT+6EL0KWiuHO2OxQrAJZbBNR8OEAlR4OquJo20w
azAOBgNVHQ8BAf8EBAMCAaYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMB
MA8GA1UdEwEB/wQFMAMBAf8wKQYDVR0OBCIEINFncJGZgtwNy6Yey6awrjS4NuLf
HqJ0ECN42d+/SFgXMAoGCCqBHM9VAYN1A0gAMEUCIQDS4BwsVxr9+bA2ecOaqh4v
sJ/YW8o3/jzo7qieTyp/ZwIgIHetgybdy1pnLrXSQ18M2NPrzlZ8eyQ5I9w/iWAO
VuU=
-----END CERTIFICATE-----
`
	p, _ := pem.Decode([]byte(certStr))
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		fmt.Print(err.Error())
	}
	fmt.Printf("Certificate:\n%v\n", cert)
	chains, err := cert.Verify(x509.VerifyOptions{})
	if err != nil {
		fmt.Print(err.Error())
	}
	fmt.Printf("Chains:\n%v\n", chains)
}
func testEcdsa() {
	k, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		fmt.Print(err)
	}
	hash1 := sha256.Sum256([]byte("Hello"))
	r, s, err := ecdsa.Sign(nil, k, hash1[:])
	pass := ecdsa.Verify(&k.PublicKey, hash1[:], r, s)
	if !pass {
		fmt.Print("no pass!!!!!")
	} else {
		fmt.Print("pass")
	}
}
