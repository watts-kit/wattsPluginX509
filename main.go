package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	l "git.scc.kit.edu/lukasburgey/wattsPluginLib"
	//"github.com/spacemonkeygo/openssl"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

var (
	err error
)

const (
	caCertificateValidity = 365 * 24 * time.Hour
	rsaBits               = 4096
)

// writes certificate and key to Conf["ca_dir"]
func createCaCertificate(pi l.Input) {
	caCertificateDir := pi.Conf["ca_dir"].(string)
	caCertificate := filepath.Join(caCertificateDir, "ca_certificate.pem")
	caCertificateKey := filepath.Join(caCertificateDir, "ca_certificate_key.pem")

	var priv *rsa.PrivateKey
	priv, err = rsa.GenerateKey(rand.Reader, rsaBits)
	l.Check(err, 1, "generating rsa key for ca certificate")

	notBefore := time.Now()
	notAfter := notBefore.Add(caCertificateValidity)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	l.Check(err, 1, "failed to generate serial number")

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{"EU"},
			Organization:       []string{"INDIGO"},
			OrganizationalUnit: []string{"TTS"},
			CommonName:         "TTS-CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create the self-signed ca certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.PublicKey, priv)
	l.Check(err, 1, "failed to create ca certificate")

	// write certificate
	certOut, err := os.Create(caCertificate)
	defer certOut.Close()
	l.Check(err, 1, "failed to open file for writing: "+caCertificate)

	certificatePEM := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	err = pem.Encode(certOut, &certificatePEM)
	l.Check(err, 1, "failed to write "+caCertificate)

	// write according key
	keyOut, err := os.OpenFile(caCertificateKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer keyOut.Close()
	l.Check(err, 1, "failed to open "+caCertificateKey)

	certificateKeyPEM := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}
	err = pem.Encode(keyOut, &certificateKeyPEM)
	l.Check(err, 1, "failed to write "+caCertificateKey)
}

func isInitialized(pi l.Input) l.Output {
	_, err = os.Open(pi.Conf["ca_certificate"].(string))
	_, err = os.Open(pi.Conf["ca_certificate"].(string))

	// if the file exists we assume its valid
	if err != nil {
		return l.Output{
			"isInitialized": false,
		}
	}

	return l.Output{
		"isInitialized": true,
	}
}

func initialize(pi l.Input) l.Output {
	createCaCertificate(pi)

	return l.Output{
		"result": "ok",
	}
}

func request(pi l.Input) l.Output {
	return l.PluginError("request failed")
}

func revoke(pi l.Input) l.Output {
	return l.PluginError("revoke failed")
}

func main() {
	pluginDescriptor := l.PluginDescriptor{
		Version: "0.1.0",
		Author:  "Lukas Burgey @ KIT within the INDIGO DataCloud Project",
		Actions: map[string]l.Action{
			"isInitialized": isInitialized,
			"initialize":    initialize,
			"request":       request,
			"revoke":        revoke,
		},
		ConfigParams: []l.ConfigParamsDescriptor{
			l.ConfigParamsDescriptor{Name: "cert_valid_duration_days", Type: "int", Default: 14},
			l.ConfigParamsDescriptor{Name: "ca_dir", Type: "string", Default: "/etc/tts/ca"},
		},
		RequestParams: []l.RequestParamsDescriptor{},
	}
	l.PluginRun(pluginDescriptor)
}
