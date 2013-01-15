/*
Package openid provides functions to use openid servers.

XRI-based URIs do work, but are not secure since they are not verified, and are only supported as the identifier.

Example RedirectURI usage:
	url, err := openid.RedirectURI("http://steamcommunity.com/openid", "http://localhost", "/")

Example Validate usage:

	if ok, id, err := openid.Validate(r.URL.Query()); ok{
		fmt.Println("id:", id)
	}

*/
package openid

import (
	"bytes"
	"code.google.com/p/go-html-transform/h5"
	"code.google.com/p/go-html-transform/html/transform"
	"encoding/xml"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

const (
	xri_global_context_symbol = "=@+$!("
	xrds_mime                 = "application/xrds+xml"
)

type xRDSIdentifier struct {
	XMLName xml.Name "Service"
	Type    []string
	URI     string
	LocalID string
}
type xRD struct {
	XMLName xml.Name "XRD"
	Service xRDSIdentifier
}
type xRDS struct {
	XMLName xml.Name "XRDS"
	XRD     xRD
}

func keyValueForm(corpus string) (o map[string]string) {
	o = make(map[string]string)
	for _, v := range strings.Split(corpus, "\n") {
		if strings.ContainsRune(v, ':') {
			split := strings.SplitN(v, ":", 2)
			o[split[0]] = split[1]
		}
	}
	return
}

/*
Function RedirectURI gets the URI the user would be directed to for an openid request with given parameters:

Identifier represents the URI the user is claiming their openid is located at.

Realm is a string that gives the user an indication of where the id will be used - 'http://example.com'.

The openid provider returns the user to (realm + returnPoint) afterward.
*/
func RedirectURI(identifier, realm, returnPoint string) (string, error) {
	//If the user's input starts with the "xri://" prefix, it MUST be stripped off, so that XRIs are used in the canonical form.
	if strings.HasPrefix(identifier, "xri://") {
		identifier = identifier[6:]
	}

	//If the first character of the resulting string is an XRI Global Context Symbol ("=", "@", "+", "$", "!") or
	//"(", as defined in Section 2.2.1 of [XRI_Syntax_2.0], then the input SHOULD be treated as an XRI.
	if runeIs(rune(identifier[0]), xri_global_context_symbol) {
		identifier = "http://xri.net/" + identifier
	} else if !strings.HasPrefix(identifier, "http://") && !strings.HasPrefix(identifier, "https://") {
		identifier = "http://" + identifier
	}

	//If the URL contains a fragment part,
	//it MUST be stripped off together with the fragment delimiter character "#".
	if index := strings.Index(identifier, "#"); index != -1 {
		identifier = identifier[index:]
	}

	rdClr, err := discover(identifier)
	if err != nil {
		return "", err
	}

	endpoint, Claimed, err := getIdentifiers(rdClr)

	if err != nil {
		return "", err
	}
	if Claimed == "" {
		Claimed = "http://specs.openid.net/auth/2.0/identifier_select"
	}
	if !strings.Contains(endpoint, "?") {
		endpoint = endpoint + "?"
	} else {
		endpoint = endpoint + "&"
	}
	return endpoint + url.Values(map[string][]string{
		"openid.claimed_id": {Claimed},
		"openid.identity":   {Claimed},
		"openid.realm":      {realm},
		"openid.return_to":  {realm + returnPoint},
		"openid.mode":       {"checkid_setup"},
		"openid.ns":         {"http://specs.openid.net/auth/2.0"},
	}).Encode(), nil
}

type validateError uint8

const (
	NO_OP_ENDPOINT validateError = iota
	DIFFERING_ENDPOINT
	NS_INCORRECT
	INCORRECT_MODE
)

func (v validateError) String() string {
	switch v {
	case NO_OP_ENDPOINT:
		return "No op endpoint provided."
	case DIFFERING_ENDPOINT:
		return "The client gave an endpoint that differed from expected."
	case NS_INCORRECT:
		return "ns in verification response was not 'http://specs.openid.net/auth/2.0'"
	case INCORRECT_MODE:
		return "Incorrect mode."
	}
	return "Invalid error."
}
func (v validateError) Error() string {
	return "openid: " + v.String()
}

/*
Function Validate takes a url.Values and returns a bool which is true if the values argument represents an openid assertion that is true, as well
as the user claimed ID.
*/
func Validate(values url.Values) (grant bool, id string, err error) {
	endpoint := values.Get("openid.op_endpoint")
	if endpoint == "" {
		err = NO_OP_ENDPOINT
		return
	}

	if values.Get("openid.mode") != "id_res" {
		err = INCORRECT_MODE
		return
	}
	values.Set("openid.mode", "check_authentication")
	var resp *http.Response
	resp, err = http.Post(endpoint, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte(values.Encode())))

	defer resp.Body.Close()

	if err != nil {
		return
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)

	if err != nil {
		return
	}

	kVs := keyValueForm(string(body))
	if kVs["ns"] != "http://specs.openid.net/auth/2.0" {
		err = NS_INCORRECT
		return
	}

	grant = kVs["is_valid"] == "true"
	id = values.Get("openid.claimed_id")
	return
}

func discover(identifier string) (io.ReadCloser, error) {
	req, err := http.NewRequest("GET", identifier, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", xrds_mime)
	resp, err := new(http.Client).Do(req)
	if err != nil {
		return nil, err
	}

	//If we've got an XRDS document, we're okay, good.
	if contentType := resp.Header.Get("Content-Type"); strings.HasPrefix(contentType, "application/xrds+xml") {
		return resp.Body, nil
		//Well, it might be in the header...
	} else if h := resp.Header.Get("X-Xrds-Location"); h != "" {
		return discover(h)
		//If it's HTML we need to search the meta tags ;.;
	} else if strings.HasPrefix(contentType, "text/html") {
		p := h5.NewParser(resp.Body)
		e := p.Parse()
		if e != nil {
			return nil, e
		}
		str, ok := discoverFromHTMLNode(p.Tree())
		if ok {
			return discover(str)
		}
	}

	return resp.Body, errors.New("Could not locate Yadis document!")

}

var yadisGetter = transform.NewSelectorQuery("meta[http-equiv=X-XRDS-Location]")

func discoverFromHTMLNode(root *h5.Node) (loc string, ok bool) {
	if r := yadisGetter.Apply(root); len(r) > 0 {
		elm := r[0]
		for _, v := range elm.Attr {
			if v.Name == "content" {
				return v.Value, true
			}
		}
	}
	return "", false
}

func getIdentifiers(xrds io.ReadCloser) (OP, Claimed string, e error) {
	defer xrds.Close()
	var xmlDoc []byte
	xmlDoc, e = ioutil.ReadAll(xrds)
	if e != nil {
		return
	}
	xrdsDocument := new(struct {
		XMLName xml.Name "XRDS"
		XRD     struct {
			Service []struct {
				Type     string
				URI      string
				Priority uint `xml:"priority,attr"`
			}
		}
	})

	xml.Unmarshal(xmlDoc, xrdsDocument)
	for _, v := range xrdsDocument.XRD.Service {
		if strings.HasPrefix(v.Type, "http://specs.openid.net/auth/2.0/server") {
			OP = v.URI
		} else if strings.HasPrefix(v.Type, "http://specs.openid.net/auth/2.0/signon") {
			Claimed = v.URI
		}
	}

	return
}

func runeIs(a rune, b string) bool {
	for _, v := range b {
		if v == a {
			return true
		}
	}
	return false
}
