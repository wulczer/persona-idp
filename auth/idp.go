package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const sessionID = "PERSONASID"
const sessionIDLen = 16

const authDocument = "/persona/login/"
const provisioningDocument = "/persona/provisioning/"

var sessionDB string
var listenAddr string
var smtpAddr string
var certIssuer string
var privateKeyPath string

var privateKey *rsa.PrivateKey
var supportDocument *[]byte

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.StringVar(&sessionDB, "session-db", "/tmp/session.db", "sqlite session store")
	flag.StringVar(&listenAddr, "listen-address", "127.0.0.1:8080", "daemon listen address")
	flag.StringVar(&smtpAddr, "smtp-address", "127.0.0.1:25", "SMTP server connection address")
	flag.StringVar(&certIssuer, "cert-issuer", "persona.dev", "hostname of the certificate issuer")
	flag.StringVar(&privateKeyPath, "private-key", "/tmp/key", "path to the private PEM key")
}

func internalError(w http.ResponseWriter, err error) {
	log.Printf("[ERROR] internal error: %s\n", err.Error())
	code := http.StatusInternalServerError
	http.Error(w, http.StatusText(code), code)
}

func checkSession(req *http.Request) (email string, err error) {
	log.Printf("[R] checking for session\n")

	cookie, err := req.Cookie(sessionID)
	if err != nil {
		log.Printf("[R] no session cookie found\n")
		err = nil
		return
	}

	db, err := sql.Open("sqlite3", sessionDB)
	if err != nil {
		return
	}
	defer db.Close()

	query := ("select email from sessions where session_id = ? " +
		"and expires > strftime('%s', 'now')")
	err = db.QueryRow(query, cookie.Value).Scan(&email)

	if err == sql.ErrNoRows {
		log.Printf("[R] session for SID %s not found\n", cookie.Value)
		err = nil
		return
	}

	log.Printf("[R] session found for email %s\n", email)
	return
}

type supportDoc struct {
	PublicKey    map[string]string `json:"public-key"`
	Auth         string            `json:"authentication"`
	Provisioning string            `json:"provisioning"`
}

func browserID(w http.ResponseWriter, req *http.Request) {
	log.Printf("[R] support document requested\n")

	w.Header().Set("Content-Type", "application/json")

	if supportDocument != nil {
		log.Printf("[R] returning cached support document\n\n")
		w.Write(*supportDocument)
		return
	}

	doc := supportDoc{
		map[string]string{
			"algorithm": "RS",
			"n":         fmt.Sprintf("%d", privateKey.PublicKey.N),
			"e":         fmt.Sprintf("%d", privateKey.PublicKey.E),
		},
		authDocument,
		provisioningDocument}

	payload, err := json.Marshal(doc)
	if err != nil {
		internalError(w, err)
		return
	}
	supportDocument = &payload

	log.Printf("[R] returning support document\n\n")

	w.Write(*supportDocument)
}

func hasSession(w http.ResponseWriter, req *http.Request) {
	log.Printf("[R] session check requested\n")
	email, err := checkSession(req)
	if err != nil {
		internalError(w, err)
		return
	}

	if email == "" || email != req.FormValue("email") {
		log.Printf("[R] session check failed\n\n")
		http.NotFound(w, req)
		return
	}

	log.Printf("[R] session check succeeded\n\n")

	w.Write([]byte("OK\n"))
}

func generateSid() (sid string, err error) {
	out := make([]byte, sessionIDLen)
	_, err = rand.Read(out)
	if err != nil {
		return
	}
	sid = hex.EncodeToString(out)
	return
}

/* workaround for https://code.google.com/p/go/issues/detail?id=5184 */
type openAuth struct {
	smtp.Auth
}

func (auth openAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	s := *server
	s.TLS = true
	return auth.Auth.Start(&s)
}

func login(w http.ResponseWriter, req *http.Request) {
	email, password := req.FormValue("email"), req.FormValue("password")

	log.Printf("[R] login requested for email %s\n", email)

	conn, err := smtp.Dial(smtpAddr)
	if err != nil {
		internalError(w, err)
		return
	}
	defer conn.Quit()

	server := strings.Split(smtpAddr, ":")[0]
	auth := openAuth{smtp.PlainAuth("", email, password, server)}

	err = conn.Auth(auth)
	if err != nil {
		log.Printf("[R] SMTP authentication failed\n\n")
		code := http.StatusUnauthorized
		http.Error(w, http.StatusText(code), code)
		return
	}

	db, err := sql.Open("sqlite3", sessionDB)
	if err != nil {
		internalError(w, err)
		return
	}
	defer db.Close()

	sid, err := generateSid()
	if err != nil {
		internalError(w, err)
		return
	}

	query := ("insert into sessions(session_id, email, expires) " +
		"values (?, ?, strftime('%s', 'now', '+1 month'))")
	_, err = db.Exec(query, sid, email)
	if err != nil {
		internalError(w, err)
		return
	}

	query = "delete from sessions where expires < strftime('%s', 'now')"
	_, err = db.Exec(query)
	if err != nil {
		internalError(w, err)
		return
	}

	cookie := http.Cookie{
		Name:     sessionID,
		Value:    sid,
		Path:     "/",
		Expires:  time.Now().AddDate(0, 1, 0),
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, &cookie)

	log.Printf("[R] login succeeded for email %s\n\n", email)

	val := url.Values{}
	val.Add("email", email)
	url := fmt.Sprintf("/persona/login/?%s", val.Encode())
	http.Redirect(w, req, url, http.StatusSeeOther)
}

func base64Encode(data []byte) []byte {
	buffer := bytes.NewBuffer(nil)
	encoder := base64.NewEncoder(base64.URLEncoding, buffer)

	encoder.Write(data)
	encoder.Close()

	return bytes.TrimRight(buffer.Bytes(), "=")
}

func dotJoin(blob1 []byte, blob2 []byte) []byte {
	return bytes.Join([][]byte{blob1, blob2}, []byte("."))
}

type principal struct {
	Email string `json:"email"`
}

type identityCert struct {
	Iss       string            `json:"iss"`
	Iat       int64             `json:"iat"`
	Exp       int64             `json:"exp"`
	PublicKey map[string]string `json:"public-key"`
	Principal principal         `json:"principal"`
}

func makeCertificate(email string, publicKey map[string]string,
	durationSec int64) (signed []byte, err error) {

	header := []byte(`{"alg": "RS256"}`)
	encodedHeader := base64Encode(header)

	iat := (time.Now().Unix() - 600) * 1000
	exp := (time.Now().Unix() + durationSec) * 1000
	cert := identityCert{certIssuer, iat, exp, publicKey, principal{email}}
	payload, err := json.Marshal(cert)
	if err != nil {
		return nil, err
	}
	encodedPayload := base64Encode(payload)

	signingBase := dotJoin(encodedHeader, encodedPayload)

	hash := sha256.New()
	hash.Write(signingBase)
	hashed := hash.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey,
		crypto.SHA256, hashed)
	if err != nil {
		return nil, err
	}
	encodedSignature := base64Encode(signature)

	return dotJoin(signingBase, encodedSignature), nil
}

func certificate(w http.ResponseWriter, req *http.Request) {
	email, err := checkSession(req)
	if err != nil {
		internalError(w, err)
		return
	}

	log.Printf("[R] certificate requested for %s\n", email)

	err = req.ParseForm()
	if err != nil {
		internalError(w, err)
		return
	}

	if email == "" || email != req.FormValue("email") {
		log.Printf("[R] invalid session\n\n")
		code := http.StatusUnauthorized
		http.Error(w, http.StatusText(code), code)
		return
	}

	certDuration := req.FormValue("certDuration")
	if certDuration == "" {
		certDuration = "86400"
	}

	durationSec, err := strconv.ParseInt(certDuration, 10, 64)
	if err != nil {
		internalError(w, err)
		return
	}

	publicKeyText := req.FormValue("publicKey")
	var publicKey map[string]string
	err = json.Unmarshal([]byte(publicKeyText), &publicKey)
	if err != nil {
		internalError(w, err)
		return
	}

	certificate, err := makeCertificate(email, publicKey, durationSec)
	if err != nil {
		internalError(w, err)
		return
	}

	log.Printf("[R] created certificate for %s\n\n", email)

	w.Write(certificate)
}

func main() {
	flag.Parse()

	keyBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	pemBlock, rest := pem.Decode(keyBytes)
	if pemBlock == nil {
		log.Fatal("no PEM data found")
	}
	if len(rest) != 0 {
		log.Fatal("leftover bytes after parsing PEM block")
	}

	privateKey, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	privateKey.Precompute()

	log.Printf("[*] IdP starting\n")

	http.HandleFunc("/browserid", browserID)
	http.HandleFunc("/has-session/", hasSession)
	http.HandleFunc("/login/", login)
	http.HandleFunc("/certificate/", certificate)

	log.Printf("[*] IdP accepting connections for %s\n", certIssuer)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
