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
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

var tmpl = template.Must(template.New("attributes").Parse(`
	<!DOCTYPE html>
	<html>
	<head>
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>{{.Name}}</title>
		<style>
			body { font-family: Arial, sans-serif; margin: 2rem; text-align: center; }
			.responsive-table {
			  width: 100%;
			  border-collapse: collapse;
			  margin: 1em auto;
			  max-width: 100%;
			}
			@media (min-width: 768px) {
			  .responsive-table {
			    width: 60%;
			  }
			}
			.responsive-table th,
			.responsive-table td {
			  border: 1px solid #ddd;
			  padding: 0.75em;
			  text-align: left;
			}
			.responsive-table th {
			  background-color: #f5f5f5;
			  font-weight: bold;
			}
			@media (max-width: 767px) {
			  .responsive-table-container {
			    overflow-x: auto;
			    -webkit-overflow-scrolling: touch;
			  }
			}
		</style>
	</head>
	<body class="responsive-table-container">
		<h1>{{.Name}}</h1>
		<p>Welcome! This page displays some details about your Single Sign On connection.</p>
		<h2>Session Details</h2>
		<table class="responsive-table">
			<tr>
				<th>Claim</th>
				<th>Value</th>
			</tr>
			<tr>
				<td>Subject (NameID)</td>
				<td>{{.JWT.JWTSessionClaims.Subject}}</td>
			</tr>
			<tr>
				<td>Issued At</td>
				<td>{{.JWT.IssuedAt}} ({{.JWT.JWTSessionClaims.IssuedAt}})</td>
			</tr>
			<tr>
				<td>Expires At</td>
				<td>{{.JWT.ExpiresAt}} ({{.JWT.JWTSessionClaims.ExpiresAt}})</td>
			</tr>
		</table>
		<h2>SAML Details</h2>
		<table class="responsive-table">
			<tr>
				<th>Item</th>
				<th>Value</th>
			</tr>
			<tr>
				<td>NameID Value</td>
				<td>{{.SamlInfo.NameidValue}}</td>
			</tr>
			<tr>
				<td>NameID Format</td>
				<td>{{.SamlInfo.NameidFormat}}</td>
			</tr>
			<tr>
				<td>Session Index</td>
				<td>{{.SamlInfo.SessionIndex}}</td>
			</tr>
			{{ if .SamlInfo.AuthnContextClassRef }}
			<tr>
				<td>Authn Context Class Ref</td>
				<td>{{.SamlInfo.AuthnContextClassRef}}</td>
			</tr>
			{{ end }}
			{{ if .SamlInfo.AuthenticatingAuthority }}
			<tr>
				<td>Authenticating Authority</td>
				<td>{{.SamlInfo.AuthenticatingAuthority}}</td>
			</tr>
			{{ end }}
		</table>
		<h2>SAML Attributes</h2>
		<table class="responsive-table">
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

	// Get AuthnContextClassRef and AuthenticatingAuthority from AuthnStatement
	if len(assertion.AuthnStatements) > 0 {
		authnStatement := assertion.AuthnStatements[0]
		authnContext := authnStatement.AuthnContext
		if authnContextClassRef := authnContext.AuthnContextClassRef.Value; authnContextClassRef != "" {
			jwtSession.Attributes["AuthnContextClassRef"] = []string{authnContextClassRef}
		}
		// can't complete until this is fixed in crewjam/saml - https://github.com/crewjam/saml/blob/346540312f721498fc75e69637d9250dd89f230b/schema.go#L1161
	}

	return jwtSession, nil
}

func (c JWTSessionCodec) Encode(s samlsp.Session) (string, error) {
	return c.Inner.Encode(s)
}

func (c JWTSessionCodec) Decode(signed string) (samlsp.Session, error) {
	return c.Inner.Decode(signed)
}

type JWTSessionClaimsWithDates struct {
	samlsp.JWTSessionClaims
	ExpiresAt string `json:"expires_at"`
	IssuedAt  string `json:"issued_at"`
}

type attribute struct {
	Name   string
	Values string
}

type samlDetails struct {
	NameidValue             string
	NameidFormat            string
	SessionIndex            string
	AuthnContextClassRef    string
	AuthenticatingAuthority string
}

type templateData struct {
	Name       string
	JWT        JWTSessionClaimsWithDates `json:"-"`
	SamlInfo   samlDetails
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
	nameidFormat := os.Getenv("SAML_NAMEID_FORMAT")

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
	sp.ServiceProvider.AuthnNameIDFormat = saml.UnspecifiedNameIDFormat
	if nameidFormat != "" {
		switch nameidFormat {
		case "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress":
			sp.ServiceProvider.AuthnNameIDFormat = saml.EmailAddressNameIDFormat
		case "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent":
			sp.ServiceProvider.AuthnNameIDFormat = saml.PersistentNameIDFormat
		case "urn:oasis:names:tc:SAML:2.0:nameid-format:transient":
			sp.ServiceProvider.AuthnNameIDFormat = saml.TransientNameIDFormat
		default:
			log.Println("Invalid SAML_NAMEID_FORMAT provided, using unspecified format")
		}
	}

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

		// convert expiresAt and issuedAt from int64 to date strings
		jwAttributeWithDates := JWTSessionClaimsWithDates{
			JWTSessionClaims: jwtAttributes,
			ExpiresAt:        time.Unix(jwtAttributes.ExpiresAt, 0).Format("2006-01-02 15:04:05"),
			IssuedAt:         time.Unix(jwtAttributes.IssuedAt, 0).Format("2006-01-02 15:04:05"),
		}

		attributes := customSession.GetAttributes()

		// if nameid and nameidformat are in attributes, put them in the a nameid struct to pass to the template
		samlInfo := samlDetails{
			NameidValue:             "",
			NameidFormat:            "",
			SessionIndex:            "",
			AuthnContextClassRef:    "",
			AuthenticatingAuthority: "",
		}
		if nameIDValues, ok := attributes["NameID"]; ok && len(nameIDValues) > 0 {
			samlInfo.NameidValue = nameIDValues[0]
			delete(attributes, "NameID")
			if nameIDFormatValues, ok := attributes["NameIDFormat"]; ok && len(nameIDFormatValues) > 0 {
				samlInfo.NameidFormat = nameIDFormatValues[0]
				delete(attributes, "NameIDFormat")
			}
		}
		if _, ok := attributes["SessionIndex"]; ok {
			samlInfo.SessionIndex = attributes["SessionIndex"][0]
			delete(attributes, "SessionIndex")
		}
		if _, ok := attributes["AuthnContextClassRef"]; ok {
			samlInfo.AuthnContextClassRef = attributes["AuthnContextClassRef"][0]
			delete(attributes, "AuthnContextClassRef")
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
			JWT:        jwAttributeWithDates,
			SamlInfo:   samlInfo,
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
