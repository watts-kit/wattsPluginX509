package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	l "git.scc.kit.edu/lukasburgey/wattsPluginLib"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type CA struct {
	CACertificate    x509.Certificate
	CACertificatePEM pem.Block
	CAKey            rsa.PrivateKey
}

const (
	// 10 years
	caCertificateValidity = 10 * 365 * 24 * time.Hour
	// TODO make configurable
	caCertificateRsaBits = 4096
	// TODO make configurable
	userCertificateRsaBits = 2048
	// TODO make configurable
	userKeyPasswordLength = 0
	caCertificateName     = "WaTTS-CA-Certificate.pem"
	caCertificateKeyName  = "WaTTS-CA-Certificate-Key.pem"
)

var (
	err    error
	caName = pkix.Name{
		Country:            []string{"EU"},
		Organization:       []string{"INDIGO"},
		OrganizationalUnit: []string{"TTS"},
		CommonName:         "TTS-CA",
	}

	caCertificateTemplate = x509.Certificate{
		SerialNumber:          getSerialNumber(),
		Subject:               caName,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA: true,
	}

	userCertificateTemplate = x509.Certificate{
		SerialNumber: getSerialNumber(),
		Subject: pkix.Name{
			Country:            []string{"EU"},
			Organization:       []string{"INDIGO"},
			OrganizationalUnit: []string{"TTS"},
		},
		Issuer:                caName,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA: false,
	}

	shortIssuer = map[string]string{
		"https://iam-test.indigo-datacloud.eu/": "indigo-iam-test",
		"https://accounts.google.com":           "google",
		"https://issuer.example.com":            "example",
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

func generateRsaKeypair(bits int, passwordLength int) (privateKey *rsa.PrivateKey) {
	// generate the rsa key for the certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	l.Check(err, 1, "generating rsa key for certificate")

	// TODO
	if passwordLength > 0 {
	}
	return
}

// creates a new ca certificate and key
// after init readCA() can be used to load the ca
func initCA(pi l.Input) {
	// directory for the pem files to be saved
	caCertificateDir := pi.Conf["ca_dir"].(string)

	// create ca key
	privateKey := generateRsaKeypair(caCertificateRsaBits, 0)

	// set certificate valid duration
	notBefore := time.Now()
	caCertificateTemplate.NotBefore = notBefore
	caCertificateTemplate.NotAfter = notBefore.Add(caCertificateValidity)

	// create ca certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &caCertificateTemplate, &caCertificateTemplate, &privateKey.PublicKey, privateKey)
	l.Check(err, 1, "creating ca certificate")

	// write ca cerficate to pem file
	caCertificatePEM := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	caCertificatePath := filepath.Join(caCertificateDir, caCertificateName)
	certOut, err := os.OpenFile(caCertificatePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer certOut.Close()
	l.Check(err, 1, "opening file for ca certificate")
	err = pem.Encode(certOut, &caCertificatePEM)
	l.Check(err, 1, "writing pem file for ca certificate")

	// write ca key to pem file
	caKeyPEM := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	caKeyPath := filepath.Join(caCertificateDir, caCertificateKeyName)
	keyOut, err := os.OpenFile(caKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer keyOut.Close()
	l.Check(err, 1, "opening file for ca key")
	err = pem.Encode(keyOut, &caKeyPEM)
	l.Check(err, 1, "pem encoding ca key")

	return
}

func readCA(pi l.Input) CA {
	caCertificateDir := pi.Conf["ca_dir"].(string)

	// CACertificate
	caCertificatePath := filepath.Join(caCertificateDir, caCertificateName)
	caCertBytes, err := ioutil.ReadFile(caCertificatePath)
	l.Check(err, 1, "reading ca certificate")
	// ignoring "pem rest" here
	caCertificatePEM, _ := pem.Decode(caCertBytes)
	if caCertificatePEM == nil {
		l.PluginError("decoding ca certificate")
	}
	caCertificate, err := x509.ParseCertificate(caCertificatePEM.Bytes)
	l.Check(err, 1, "parsing ca certificate")
	if caCertificate == nil {
		l.PluginError("ca certificate is nil")
	}

	// CAKey
	caKeyPath := filepath.Join(caCertificateDir, caCertificateKeyName)
	caKeyBytes, err := ioutil.ReadFile(caKeyPath)
	l.Check(err, 1, "reading ca key")
	// ignoring "pem rest" here
	caKeyPEM, _ := pem.Decode(caKeyBytes)
	if caKeyPEM == nil {
		l.PluginError("decoding ca key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(caKeyPEM.Bytes)
	l.Check(err, 1, "parsing ca key")

	return CA{
		CACertificate:    *caCertificate,
		CACertificatePEM: *caCertificatePEM,
		CAKey:            *privateKey,
	}
}

func createUserCertificate(pi l.Input, ca CA) (pem.Block, pem.Block) {

	// generate rsa key for the user certificate
	privateKey := generateRsaKeypair(userCertificateRsaBits, userKeyPasswordLength)
	rsaKeyPEM := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// set certificate valid duration
	validDuration, err := time.ParseDuration(pi.Conf["cert_valid_duration"].(string))
	l.Check(err, 1, "parsing valid duration")

	notBefore := time.Now()
	userCertificateTemplate.NotBefore = notBefore
	userCertificateTemplate.NotAfter = notBefore.Add(validDuration)

	// Common name: subject @ short issuer
	subject := pi.UserInfo["sub"].(string)
	issuer := shortenIssuer(pi.UserInfo["iss"].(string))
	commonName := subject + "@" + issuer
	userCertificateTemplate.Subject.CommonName = commonName

	// create user certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &userCertificateTemplate, &ca.CACertificate, &(privateKey.PublicKey), &ca.CAKey)
	l.Check(err, 1, "creating certificate")

	return pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}, rsaKeyPEM
}

// --- api methods ---
func isInitialized(pi l.Input) (o l.Output) {
	o = l.Output{"isInitialized": true}

	// ca dir
	caCertificateDir := pi.Conf["ca_dir"].(string)
	_, err = os.Stat(caCertificateDir)
	if os.IsNotExist(err) {
		o = l.Output{"isInitialized": false}
	}

	// ca certificate file
	_, err = os.Stat(filepath.Join(caCertificateDir, caCertificateName))
	if os.IsNotExist(err) {
		o = l.Output{"isInitialized": false}
	}

	return
}

func initialize(pi l.Input) l.Output {
	// create the ca dir
	err = os.MkdirAll(pi.Conf["ca_dir"].(string), 0700)
	l.Check(err, 1, "creating ca_dir")

	initCA(pi)

	return l.Output{"result": "ok"}
}

func request(pi l.Input) l.Output {
	// get our certificate for signing the user certificate
	ca := readCA(pi)

	certPEM, keyPEM := createUserCertificate(pi, ca)

	credential := []l.Credential{
		l.TextFileCredential("CA Certificate", string(pem.EncodeToMemory(&ca.CACertificatePEM)), 30, 64, "ca-certificate.pem"),
		l.TextFileCredential("Certificate", string(pem.EncodeToMemory(&certPEM)), 25, 64, "certificate.pem"),
		l.TextFileCredential("Key", string(pem.EncodeToMemory(&keyPEM)), 15, 64, "key.pem"),
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
			l.ConfigParamsDescriptor{Name: "cert_valid_duration", Type: "string", Default: "264h"},
			l.ConfigParamsDescriptor{Name: "ca_dir", Type: "string", Default: "/etc/tts/ca"},
		},
		RequestParams: []l.RequestParamsDescriptor{},
	}
	l.PluginRun(pluginDescriptor)
}
