package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	l "git.scc.kit.edu/lukasburgey/wattsPluginLib"
	"git.scc.kit.edu/lukasburgey/wattsPluginLib/keyGen"
	"github.com/alexflint/go-filemutex"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CA important ca parameters
type CA struct {
	CACertificate    *x509.Certificate
	CACertificatePEM *pem.Block
	CAKey            *rsa.PrivateKey
	CADir            string
}

const (
	// 10 years
	caCertificateValidity = 10 * 365 * 24 * time.Hour
	// TODO make configurable
	caCertificateRsaBits = 4096
	// TODO make configurable
	userCertificateRsaBits = 2048
	// TODO make configurable
	userKeyPasswordLength = 16
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
		SerialNumber:          big.NewInt(0),
		Subject:               caName,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA: true,
	}

	userCertificateTemplate = x509.Certificate{
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

func (ca *CA) getSerialNumber(pi l.Input) *big.Int {

	serialFileName := "serials"
	serialFilePath := filepath.Join(ca.CADir, serialFileName)
	lockPath := filepath.Join(ca.CADir, serialFileName+".lock")
	mutex, err := filemutex.New(lockPath)
	l.Check(err, 1, "unable to initialize lock file")

	serialNumber := big.NewInt(0)
	// we use the sha1 hash of watts_uid || time.Now as a serialNumber
	uid := []byte(pi.WaTTSUserID)
	currentTime, err := time.Now().MarshalText()
	l.Check(err, 1, "marhaling time")
	serialNumberData := append(uid, currentTime...)
	hash := sha1.Sum(serialNumberData)
	// we need to convert the fixed length array into a slice here using [:]
	serialBytes := hash[:]
	serialNumber.SetBytes(serialBytes)

	mutex.Lock()
	defer mutex.Unlock()

	if _, err := os.Stat(serialFilePath); err == nil {
		// check if the serial is already used
		serialFileBytes, err := ioutil.ReadFile(serialFilePath)
		l.Check(err, 1, "reading serial file")

		// if the sn is already taken we take a new currentTime and try again
		if bytes.Contains(serialFileBytes, serialBytes) {
			return ca.getSerialNumber(pi)
		}
	}

	// write the serialNumber to the file
	serialFile, err := os.OpenFile(serialFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	l.Check(err, 1, "opening serial file")
	defer func() { err = serialFile.Close(); l.Check(err, 1, "closing file") }()

	_, err = serialFile.Write(serialBytes)
	l.Check(err, 1, "writing to serial file")

	return serialNumber
}

// synchronized with a mutex
// creates a new ca certificate and key
// after init readCA() can be used to load the ca
func initCA(pi l.Input) {
	// directory for the pem files to be saved
	caCertificateDir := pi.Conf["ca_dir"].(string)
	lockPath := filepath.Join(caCertificateDir, "ca.lock")
	mutex, err := filemutex.New(lockPath)
	l.Check(err, 1, "unable to initialize lock file")

	mutex.Lock()
	defer mutex.Unlock()

	// create ca key
	privateKey := keyGen.GenerateRSAKey(caCertificateRsaBits)

	// set certificate valid duration
	notBefore := time.Now()
	caCertificateTemplate.NotBefore = notBefore
	caCertificateTemplate.NotAfter = notBefore.Add(caCertificateValidity)
	serialNumber := big.NewInt(0)
	caCertificateTemplate.SerialNumber = serialNumber

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
	defer func() { err = certOut.Close(); l.Check(err, 1, "closing file") }()
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
	defer func() { err = keyOut.Close(); l.Check(err, 1, "closing file") }()
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
		CACertificate:    caCertificate,
		CACertificatePEM: caCertificatePEM,
		CAKey:            privateKey,
		CADir:            caCertificateDir,
	}
}

func (ca *CA) createUserCertificate(pi l.Input, serialNumber *big.Int) (certificatePEM *pem.Block, privateKey *rsa.PrivateKey) {
	certificatePEM = new(pem.Block)

	// generate rsa key for the user certificate
	privateKey = keyGen.GenerateRSAKey(userCertificateRsaBits)

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
	userCertificateTemplate.SerialNumber = serialNumber

	// create user certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &userCertificateTemplate, ca.CACertificate, &(privateKey.PublicKey), ca.CAKey)
	l.Check(err, 1, "creating certificate")

	*certificatePEM = pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	return
}

// synchronized with a mutex (across processes)
func (ca *CA) updateCRL(revokedCertificate pkix.RevokedCertificate) {
	// synchronize the access to updateCRL
	crlName := "crl.der"
	lockPath := filepath.Join(ca.CADir, crlName+".lock")
	mutex, err := filemutex.New(lockPath)
	l.Check(err, 1, "unable to initialize lock file")
	mutex.Lock()
	defer mutex.Unlock()

	crlPath := filepath.Join(ca.CADir, crlName)

	// create certificate revocation list
	// RFC 5280 Section 5.1.2.4
	thisUpdate := time.Now()

	// RFC 5280 Section 5.1.2.5
	// the problem is that we don't know when we will next issue a crl
	// so we just set to "in one year"
	nextUpdate := time.Now().Add(365 * 24 * time.Hour)

	var revokedCertificates []pkix.RevokedCertificate

	// if there is no old crl we only revoke the current certificate
	// if there is one we "append" to the crl
	if _, err := os.Stat(crlPath); os.IsNotExist(err) {
		revokedCertificates = []pkix.RevokedCertificate{revokedCertificate}

	} else {
		derBytes, err := ioutil.ReadFile(crlPath)
		l.Check(err, 1, "reading old crl file")

		certificateList, err := x509.ParseCRL(derBytes)
		l.Check(err, 1, "parsing old crl file")

		// TODO check signature of old crl

		revokedCertificates = append(certificateList.TBSCertList.RevokedCertificates, revokedCertificate)
	}

	// create the certificate revocation list
	crlBytes, err := ca.CACertificate.CreateCRL(rand.Reader, ca.CAKey, revokedCertificates, thisUpdate, nextUpdate)
	l.Check(err, 1, "error creating certificate revocation list")

	// TODO check if this overwrites the old crl
	// write it to a file
	err = ioutil.WriteFile(crlPath, crlBytes, 0600)
	l.Check(err, 1, "error writing certificate revocation list")
}

// --- api methods ---
func isInitialized(pi l.Input) l.Output {
	initialized := true
	caCertificateDir := pi.Conf["ca_dir"].(string)
	caCertificatePath := filepath.Join(caCertificateDir, caCertificateName)
	caKeyPath := filepath.Join(caCertificateDir, caCertificateKeyName)

	if _, err = os.Stat(caCertificateDir); os.IsNotExist(err) {
		initialized = false
	}
	if _, err = os.Stat(caCertificatePath); os.IsNotExist(err) {
		initialized = false
	}
	if _, err = os.Stat(caKeyPath); os.IsNotExist(err) {
		initialized = false
	}

	return l.Output{"isInitialized": initialized}
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
	serialNumber := ca.getSerialNumber(pi)
	l.Check(err, 1, "marhaling serialNumber")

	certificatePEM, privateKey := ca.createUserCertificate(pi, serialNumber)

	credential := []l.Credential{
		l.TextFileCredential("CA Certificate", string(pem.EncodeToMemory(ca.CACertificatePEM)), 30, 64, "ca-certificate.pem"),
		l.TextFileCredential("Certificate", string(pem.EncodeToMemory(certificatePEM)), 25, 64, "certificate.pem"),
	}
	if userKeyPasswordLength > 0 {
		password := keyGen.GeneratePassword(userKeyPasswordLength)

		credential = append(
			credential,
			l.TextCredential("Password for key", password),
			l.TextFileCredential("Private key", string(pem.EncodeToMemory(keyGen.MarshalRSAKeyEncryptedPEM(privateKey, password))), 15, 64, "key.pem"))
	} else {
		credential = append(
			credential,
			l.TextFileCredential("Privat key", string(pem.EncodeToMemory(keyGen.MarshalRSAKeyPEM(privateKey))), 15, 64, "key.pem"))
	}

	state := serialNumber.Text(16)
	return l.PluginGoodRequest(credential, state)
}

func revoke(pi l.Input) l.Output {
	ca := readCA(pi)

	serialNumber := big.NewInt(0)
	serialNumber.SetString(pi.CredentialState, 16)

	revokedCertificate := pkix.RevokedCertificate{
		SerialNumber:   serialNumber,
		RevocationTime: time.Now(),
	}

	ca.updateCRL(revokedCertificate)

	return l.PluginGoodRevoke()
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
