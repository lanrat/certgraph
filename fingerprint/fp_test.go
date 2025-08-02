package fingerprint_test

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/lanrat/certgraph/fingerprint"
)

const rawCert = "MIID/TCCA4KgAwIBAgIQBV74EmrgijxarGYRe4auizAKBggqhkjOPQQDAzBWMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMTAwLgYDVQQDEydEaWdpQ2VydCBUTFMgSHlicmlkIEVDQyBTSEEzODQgMjAyMCBDQTEwHhcNMjIwNDIwMDAwMDAwWhcNMjMwNDIwMjM1OTU5WjBmMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEVMBMGA1UEChMMR2l0SHViLCBJbmMuMRMwEQYDVQQDEwpnaXRodWIuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjkAQ9bMD0dVDhUlfevxOChhxQME0Sb7kZr7+3T/gW6CW4eduvDZxsQUwa37mhUXMzF88gh+FsUy9TieoqZhasKOCAiAwggIcMB8GA1UdIwQYMBaAFAq8CCkXjKU5bXoOzjPHLrPt+8N6MB0GA1UdDgQWBBQJJ/08CmhEtgPojKO+W3TVwfJnaTAlBgNVHREEHjAcggpnaXRodWIuY29tgg53d3cuZ2l0aHViLmNvbTAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMIGbBgNVHR8EgZMwgZAwRqBEoEKGQGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRMU0h5YnJpZEVDQ1NIQTM4NDIwMjBDQTEtMS5jcmwwRqBEoEKGQGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRMU0h5YnJpZEVDQ1NIQTM4NDIwMjBDQTEtMS5jcmwwPgYDVR0gBDcwNTAzBgZngQwBAgIwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMIGFBggrBgEFBQcBAQR5MHcwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBPBggrBgEFBQcwAoZDaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VExTSHlicmlkRUNDU0hBMzg0MjAyMENBMS0xLmNydDAJBgNVHRMEAjAAMBMGCisGAQQB1nkCBAMBAf8EAgUAMAoGCCqGSM49BAMDA2kAMGYCMQC/16+UbmbTo4bcahQGLY2+SrWtge+DC2dcEY2pv1Cwn3YUi51uqEE+v7U6PUvWWbQCMQCslhV/IibG55Uoa6F/hNpa21ZqEhp38u7CHTFb+6HGbLi0CtbSjgc1mn/yEt5pFu0="
const fpHashHex = "46a1fe1780fd9a05a5529906ed08a5fea2cfe63567c9fdeb62c18ba74fae35d5"
const fpHashB64 = "RqH+F4D9mgWlUpkG7Qil/qLP5jVnyf3rYsGLp0+uNdU="

func TestFromHashBytes(t *testing.T) {

	data, err := base64.StdEncoding.DecodeString(rawCert)
	if err != nil {
		t.Errorf("error on b64 decode: %s", err.Error())
	}

	dataHashBytes := sha256.Sum256(data)

	fp := fingerprint.FromHashBytes(dataHashBytes[:])
	uppercaseHexHash := strings.ToUpper(fpHashHex)
	hashHex := fp.HexString()

	if hashHex != uppercaseHexHash {
		t.Errorf("fingerprint error, expected hex hash [%s] got [%s]", uppercaseHexHash, hashHex)
	}

	hashB64 := fp.B64Encode()

	if hashB64 != fpHashB64 {
		t.Errorf("fingerprint error, expected b64 hash [%s] got [%s]", hashB64, fpHashB64)
	}
}

func TestFromRawCertBytes(t *testing.T) {

	data, err := base64.StdEncoding.DecodeString(rawCert)
	if err != nil {
		t.Errorf("error on b64 decode: %s", err.Error())
	}

	fp := fingerprint.FromRawCertBytes(data)
	uppercaseHash := strings.ToUpper(fpHashHex)
	hashHex := fp.HexString()

	if hashHex != uppercaseHash {
		t.Errorf("fingerprint error, expected hex hash [%s] got [%s]", uppercaseHash, hashHex)
	}

	hashB64 := fp.B64Encode()

	if hashB64 != fpHashB64 {
		t.Errorf("fingerprint error, expected b64 hash [%s] got [%s]", hashB64, fpHashB64)
	}
}

func TestFromB64Hash(t *testing.T) {

	fp, err := fingerprint.FromB64Hash(fpHashB64)
	if err != nil {
		t.Fatalf("FromB64Hash failed: %v", err)
	}

	uppercaseHash := strings.ToUpper(fpHashHex)
	hashHex := fp.HexString()

	if hashHex != uppercaseHash {
		t.Errorf("fingerprint error, expected hex hash [%s] got [%s]", uppercaseHash, hashHex)
	}

	hashB64 := fp.B64Encode()

	if hashB64 != fpHashB64 {
		t.Errorf("fingerprint error, expected b64 hash [%s] got [%s]", hashB64, fpHashB64)
	}
}

func TestFromHexHash(t *testing.T) {

	fp, err := fingerprint.FromHexHash(fpHashHex)
	if err != nil {
		t.Fatalf("FromHexHash failed: %v", err)
	}

	hashB64 := fp.B64Encode()

	if fpHashB64 != hashB64 {
		t.Errorf("fingerprint error, expected b64 hash [%s] got [%s]", fpHashHex, hashB64)
	}
}
