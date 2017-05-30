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

const (
	caCertificateValidity = 365 * 24 * time.Hour
	rsaBits               = 4096
)

var (
	err                   error
	caCertificateTemplate = x509.Certificate{
		SerialNumber: getSerialNumber(),
		Subject: pkix.Name{
			Country:            []string{"EU"},
			Organization:       []string{"INDIGO"},
			OrganizationalUnit: []string{"TTS"},
			CommonName:         "TTS-CA",
		},
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	userCertificateTemplate = x509.Certificate{
		SerialNumber: getSerialNumber(),
		Subject: pkix.Name{
			Country:            []string{"EU"},
			Organization:       []string{"INDIGO"},
			OrganizationalUnit: []string{"TTS"},
		},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	shortIssuer = map[string]string{
		"https://iam-test.indigo-datacloud.eu/": "indigo-iam-test",
		"https://accounts.google.com":           "google",
	}
)

func shortenIssuer(issuer string) string {
	if si, ok := shortIssuer[issuer]; ok {
		return si
	}
	return issuer
}

func getSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	l.Check(err, 1, "failed to generate serial number")
	return serialNumber
}

func writeCaCertificate(pi l.Input, caCertificatePEM *pem.Block, caCertificateKeyPEM *pem.Block) {
	caCertificateDir := pi.Conf["ca_dir"].(string)
	caCertificate := filepath.Join(caCertificateDir, "ca_certificate.pem")
	caCertificateKey := filepath.Join(caCertificateDir, "ca_certificate_key.pem")

	// write certificate
	certOut, err := os.Create(caCertificate)
	defer certOut.Close()
	l.Check(err, 1, "failed to open file for writing: "+caCertificate)

	err = pem.Encode(certOut, caCertificatePEM)
	l.Check(err, 1, "failed to write "+caCertificate)

	// write according key
	keyOut, err := os.OpenFile(caCertificateKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer keyOut.Close()
	l.Check(err, 1, "failed to open "+caCertificateKey)

	err = pem.Encode(keyOut, caCertificateKeyPEM)
	l.Check(err, 1, "failed to write "+caCertificateKey)
}

func readCaCertificate(pi l.Input) (caCertificate x509.Certificate) {
	// TODO
	return x509.Certificate{}
}

func createCertificate(template *x509.Certificate, signTemplate *x509.Certificate) (certificatePEM pem.Block, certificateKeyPEM pem.Block) {
	var priv *rsa.PrivateKey
	priv, err = rsa.GenerateKey(rand.Reader, rsaBits)
	l.Check(err, 1, "generating rsa key for certificate")

	// create the self-signed ca certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, signTemplate, priv.PublicKey, priv)
	l.Check(err, 1, "creating certificate")

	certificatePEM = pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}

	certificateKeyPEM = pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}
	return
}

func createCaCertificate(pi l.Input) (pem.Block, pem.Block) {
	// set certificate valid duration
	notBefore := time.Now()
	caCertificateTemplate.NotBefore = notBefore
	caCertificateTemplate.NotAfter = notBefore.Add(caCertificateValidity)

	// two times the same template implies a selfsigned certificate
	return createCertificate(&caCertificateTemplate, &caCertificateTemplate)
}

func createUserCertificate(pi l.Input) (pem.Block, pem.Block) {
	// get our certificate for signing the user certificate
	caCertificate := readCaCertificate(pi)

	// set certificate valid duration
	validDuration, err := time.ParseDuration(pi.Conf["cert_valid_duration"].(string))
	l.Check(err, 1, "parsing valid duration")

	notBefore := time.Now()
	userCertificateTemplate.NotBefore = notBefore
	userCertificateTemplate.NotAfter = notBefore.Add(validDuration)

	// TODO set CommonName
	// Common name: subject @ short issuer
	subject := pi.UserInfo["sub"].(string)
	issuer := shortenIssuer(pi.UserInfo["iss"].(string))
	commonName := subject + "@" + issuer
	userCertificateTemplate.Subject.CommonName = commonName

	return createCertificate(&userCertificateTemplate, &caCertificate)
}

// --- api methods ---
func isInitialized(pi l.Input) l.Output {
	_, err = os.Stat(pi.Conf["ca_dir"].(string))

	// if the dir exists we assume the ca cert is valid
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
	cert, certKey := createCaCertificate(pi)
	writeCaCertificate(pi, &cert, &certKey)

	return l.Output{"result": "ok"}
}

func request(pi l.Input) l.Output {
	certPEM, keyPEM := createUserCertificate(pi)

	credential := []l.Credential{
		l.Credential{Name: "certificate (pem)", Type: "string", Value: string(pem.EncodeToMemory(&certPEM))},
		l.Credential{Name: "key (pem)", Type: "string", Value: string(pem.EncodeToMemory(&keyPEM))},
	}
	state := "certificate issued"
	return l.PluginGoodRequest(credential, state)
}

func revoke(pi l.Input) l.Output {
	return l.PluginError("revoke not implemented")
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
			// this value will be parsed using time.ParseDuration()
			l.ConfigParamsDescriptor{Name: "cert_valid_duration_days", Type: "string", Default: "264h"},
			l.ConfigParamsDescriptor{Name: "ca_dir", Type: "string", Default: "/etc/tts/ca"},
		},
		RequestParams: []l.RequestParamsDescriptor{},
	}
	l.PluginRun(pluginDescriptor)
}
