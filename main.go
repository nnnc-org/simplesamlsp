package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

var tmpl = template.Must(template.New("attributes").Parse(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>{{.Name}}</title>
		<style>
			body { font-family: Arial, sans-serif; margin: 2rem; }
			table { border-collapse: collapse; width: 50%; }
			th, td { border: 1px solid #ccc; padding: 0.5rem; text-align: left; }
			th { background-color: #f0f0f0; }
		</style>
	</head>
	<body>
		<h1>{{.Name}}</h1>
		<p>Welcome! This page displays some details about your Single Sign On connection.</p>
		<h2>Session Details</h2>
		<table>
			<tr>
				<th>Claim</th>
				<th>Value</th>
			</tr>
			<tr>
				<td>Subject (NameID)</td>
				<td>{{.JWT.Subject}}</td>
			</tr>
			<tr>
				<td>Issued At</td>
				<td>{{.JWT.IssuedAt}}</td>
			</tr>
			<tr>
				<td>Expires At</td>
				<td>{{.JWT.ExpiresAt}}</td>
			</tr>
		</table>
		<h2>NameID Details</h2>
		<table>
			<tr>
				<th>Format</th>
				<th>Value</th>
			</tr>
			<tr>
				<td>{{.NameID.Format}}</td>
				<td>{{.NameID.Value}}</td>
			</tr>
		</table>
		<h2>Attributes</h2>
		<table>
			<tr>
				<th>Attribute</th>
				<th>Values</th>
			</tr>
			{{range $index, $attr := .Attributes}}
			<tr>
				<td>{{$attr.Name}}</td>
				<td>{{$attr.Values}}</td>
			</tr>
			{{end}}
		</table>
		<br>
		<div class="center">
			<a class="pure-button pure-button-red" href="/logout">Logout</a>
		</div>
	</body>
	</html>
`))

// middleware to override JWTSessionCodec 'new' method with a custom one that adds the nameid and nameidformat as attributes
// its hacky, but we don't have access to the assertion directly from the session code
type JWTSessionCodec struct {
	Inner samlsp.JWTSessionCodec
}

var _ samlsp.SessionCodec = JWTSessionCodec{}

func (c JWTSessionCodec) New(assertion *saml.Assertion) (samlsp.Session, error) {
	Session, err := c.Inner.New(assertion)
	if err != nil {
		return Session, err
	}
	// cast to JWTSessionClaims
	jwtSession, _ := Session.(samlsp.JWTSessionClaims)

	// Add NameID and NameIDFormat as attributes
	if sub := assertion.Subject; sub != nil {
		if nameID := sub.NameID; nameID != nil {
			jwtSession.Attributes["NameID"] = []string{nameID.Value}
			if nameIDFormat := nameID.Format; nameIDFormat != "" {
				jwtSession.Attributes["NameIDFormat"] = []string{nameIDFormat}
			}
		}
	}

	return jwtSession, nil
}

func (c JWTSessionCodec) Encode(s samlsp.Session) (string, error) {
	return c.Inner.Encode(s)
}

func (c JWTSessionCodec) Decode(signed string) (samlsp.Session, error) {
	return c.Inner.Decode(signed)
}

type attribute struct {
	Name   string
	Values string
}

type nameID struct {
	Value  string
	Format string
}

type templateData struct {
	Name       string
	JWT        samlsp.JWTSessionClaims `json:"-"`
	NameID     nameID
	Attributes []attribute
}

func main() {
	// Required environment variables
	entityID := os.Getenv("SAML_ENTITY_ID")
	idpURL := os.Getenv("SAML_IDP_METADATA_URL")
	appURL := os.Getenv("APP_URL")

	// Optional
	certFile := os.Getenv("SAML_CERT_FILE")
	keyFile := os.Getenv("SAML_KEY_FILE")
	appName := os.Getenv("APP_NAME")

	if idpURL == "" || appURL == "" {
		log.Fatal("Missing required environment variables: SAML_ENTITY_ID, SAML_IDP_METADATA_URL, APP_URL")
	}

	var signingCert *tls.Certificate

	if certFile != "" && keyFile != "" {
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("Failed to load cert/key: %v", err)
		}
		signingCert = &pair
		log.Println("Loaded signing certificate and key.")
	} else {
		log.Println("No signing cert/key provided. Running in unsigned mode (not recommended for production).")
	}

	rootURL := mustParseURL(appURL)

	idpMetadataURL, err := url.Parse(idpURL)
	if err != nil {
		panic(err) // TODO handle error
	}
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient, *idpMetadataURL)

	opts := samlsp.Options{
		URL:         *rootURL,
		IDPMetadata: idpMetadata,
		//EntityID:          entityID,
		AllowIDPInitiated: true,
	}

	if entityID != "" {
		opts.EntityID = entityID
	}

	if signingCert != nil {
		opts.Certificate = signingCert.Leaf
		opts.Key = signingCert.PrivateKey.(*rsa.PrivateKey)
	}

	sp, err := samlsp.New(opts)
	if err != nil {
		log.Fatalf("Error creating SAML SP: %v", err)
	}

	// override the default session provider to use our custom JWTSessionCodec
	sessionProvider := samlsp.DefaultSessionProvider(opts)
	codec := samlsp.DefaultSessionCodec(opts)
	sessionProvider.Codec = JWTSessionCodec{
		Inner: codec,
	}

	sp.Session = sessionProvider

	// SAML ACS
	http.Handle("/saml/", sp)

	// /login shows attributes
	http.Handle("/", sp.RequireAccount(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := sp.Session.GetSession(r)
		if err != nil || session == nil {
			http.Error(w, "not authenticated", http.StatusUnauthorized)
			return
		}

		customSession, ok := session.(samlsp.SessionWithAttributes)
		if !ok {
			http.Error(w, "session missing attributes", http.StatusInternalServerError)
			return
		}

		// get the jwt information
		jwtAttributes := session.(samlsp.JWTSessionClaims)

		attributes := customSession.GetAttributes()

		// if nameid and nameidformat are in attributes, put them in the a nameid struct to pass to the template
		nameidValue := ""
		nameidFormat := ""
		if nameIDValues, ok := attributes["NameID"]; ok && len(nameIDValues) > 0 {
			nameidValue = nameIDValues[0]
			delete(attributes, "NameID")
			if nameIDFormatValues, ok := attributes["NameIDFormat"]; ok && len(nameIDFormatValues) > 0 {
				nameidFormat = nameIDFormatValues[0]
				delete(attributes, "NameIDFormat")
			}
		}

		nameid := nameID{
			Value:  nameidValue,
			Format: nameidFormat,
		}

		var rows []attribute
		keys := make([]string, 0, len(attributes))
		for k := range attributes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			rows = append(rows, attribute{
				Name:   k,
				Values: strings.Join(attributes[k], ", "),
			})
		}

		if appName == "" {
			appName = "SAML Attributes"
		}

		var tdata = templateData{
			Name:       appName,
			JWT:        jwtAttributes,
			NameID:     nameid,
			Attributes: rows,
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.Execute(w, tdata); err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
		}
	})))

	// /logout logs out the user
	http.Handle("/logout", sp.RequireAccount(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := sp.Session.GetSession(r)
		if err != nil || session == nil {
			http.Error(w, "not authenticated", http.StatusUnauthorized)
			return
		}
		if err := sp.Session.DeleteSession(w, r); err != nil {
			http.Error(w, "logout error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})))

	// Everything else redirects to /login
	//http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	//	http.Redirect(w, r, "/login", http.StatusFound)
	//})

	log.Println("Listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", proxyHandler(http.DefaultServeMux)))
}

// Helpers

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		log.Fatalf("invalid APP_URL: %v", err)
	}
	return u
}

func proxyHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			r.URL.Scheme = proto
		}
		if host := r.Header.Get("X-Forwarded-Host"); host != "" {
			r.URL.Host = host
		}
		h.ServeHTTP(w, r)
	})
}
