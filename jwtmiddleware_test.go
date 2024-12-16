package jwtmiddleware

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
)

// defaultAuthorizationHeaderName is the default header name where the Auth
// token should be written
const defaultAuthorizationHeaderName = "Authorization"

// userPropertyName is the property name that will be set in the request context
const userPropertyName = "custom-user-property"

// the bytes read from the keys/sample-key file
// private key generated with http://kjur.github.io/jsjws/tool_jwt.html
var privateKey []byte = nil

// TestUnauthenticatedRequest will perform requests with no Authorization header
func TestUnauthenticatedRequest(t *testing.T) {
	t.Run("Simple unauthenticated request", func(t *testing.T) {
		t.Run("Unauthenticated GET to / path should return a 200 response", func(t *testing.T) {
			w := makeUnauthenticatedRequest("GET", "/")
			if w.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", w.Code)
			}
		})
		t.Run("Unauthenticated GET to /protected path should return a 401 response", func(t *testing.T) {
			w := makeUnauthenticatedRequest("GET", "/protected")
			if w.Code != http.StatusUnauthorized {
				t.Errorf("expected status 401, got %d", w.Code)
			}
		})
	})
}

// TestUnauthenticatedRequest will perform requests with no Authorization header
func TestAuthenticatedRequest(t *testing.T) {
	var e error
	privateKey, e = readPrivateKey()
	if e != nil {
		panic(e)
	}

	t.Run("Simple unauthenticated request", func(t *testing.T) {
		t.Run("Authenticated GET to / path should return a 200 response", func(t *testing.T) {
			w := makeAuthenticatedRequest("GET", "/", map[string]interface{}{"foo": "bar"}, nil)
			if w.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", w.Code)
			}
		})

		t.Run("Authenticated GET to /protected path should return a 200 response if expected algorithm is not specified", func(t *testing.T) {
			var expectedAlgorithm jwt.SigningMethod
			w := makeAuthenticatedRequest("GET", "/protected", map[string]interface{}{"foo": "bar"}, expectedAlgorithm)
			if w.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", w.Code)
			}
			responseBytes, err := io.ReadAll(w.Body)
			if err != nil {
				t.Fatal(err)
			}
			responseString := string(responseBytes)
			if responseString != `{"text":"bar"}` {
				t.Errorf("expected response %s, got %s", `{"text":"bar"}`, responseString)
			}
		})

		t.Run("Authenticated GET to /protected path should return a 200 response if expected algorithm is correct", func(t *testing.T) {
			expectedAlgorithm := jwt.SigningMethodHS256
			w := makeAuthenticatedRequest("GET", "/protected", map[string]interface{}{"foo": "bar"}, expectedAlgorithm)
			if w.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", w.Code)
			}
			responseBytes, err := io.ReadAll(w.Body)
			if err != nil {
				t.Fatal(err)
			}
			responseString := string(responseBytes)
			if responseString != `{"text":"bar"}` {
				t.Errorf("expected response %s, got %s", `{"text":"bar"}`, responseString)
			}
		})

		t.Run("Authenticated GET to /protected path should return a 401 response if algorithm is not expected one", func(t *testing.T) {
			expectedAlgorithm := jwt.SigningMethodRS256
			w := makeAuthenticatedRequest("GET", "/protected", map[string]interface{}{"foo": "bar"}, expectedAlgorithm)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("expected status 401, got %d", w.Code)
			}
			responseBytes, err := io.ReadAll(w.Body)
			if err != nil {
				t.Fatal(err)
			}
			responseString := string(responseBytes)
			expectedResponse := "Expected RS256 signing method but token specified HS256"
			if strings.TrimSpace(responseString) != expectedResponse {
				t.Errorf("expected response %s, got %s", expectedResponse, responseString)
			}
		})
	})
}

func makeUnauthenticatedRequest(method string, url string) *httptest.ResponseRecorder {
	return makeAuthenticatedRequest(method, url, nil, nil)
}

func makeAuthenticatedRequest(method string, url string, c map[string]interface{}, expectedSignatureAlgorithm jwt.SigningMethod) *httptest.ResponseRecorder {
	r, _ := http.NewRequest(method, url, nil)
	if c != nil {
		token := jwt.New(jwt.SigningMethodHS256)
		token.Claims = jwt.MapClaims(c)
		// private key generated with http://kjur.github.io/jsjws/tool_jwt.html
		s, e := token.SignedString(privateKey)
		if e != nil {
			panic(e)
		}
		r.Header.Set(defaultAuthorizationHeaderName, fmt.Sprintf("bearer %v", s))
	}
	w := httptest.NewRecorder()
	n := createMiddleware(expectedSignatureAlgorithm)
	n.ServeHTTP(w, r)
	return w
}

func createMiddleware(expectedSignatureAlgorithm jwt.SigningMethod) http.Handler {
	// create a gorilla mux router for public requests
	publicRouter := mux.NewRouter().StrictSlash(true)
	publicRouter.Methods("GET").
		Path("/").
		Name("Index").
		Handler(http.HandlerFunc(indexHandler))

	// create a gorilla mux route for protected requests
	// the routes will be tested for jwt tokens in the default auth header
	protectedRouter := mux.NewRouter().StrictSlash(true)
	protectedRouter.Methods("GET").
		Path("/protected").
		Name("Protected").
		Handler(http.HandlerFunc(protectedHandler))

	// create a main router
	mainRouter := mux.NewRouter().StrictSlash(true)
	mainRouter.Handle("/", publicRouter)
	mainRouter.Handle("/protected", jwtMiddleware(expectedSignatureAlgorithm)(protectedRouter))
	mainRouter.Handle("/protected/{_dummy:.*}", jwtMiddleware(expectedSignatureAlgorithm)(protectedRouter))

	// apply global middlewares
	return loggingMiddleware(mainRouter)
}

func jwtMiddleware(expectedSignatureAlgorithm jwt.SigningMethod) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// JWT validation logic here
			JWT(expectedSignatureAlgorithm).HandlerWithNext(w, r, next.ServeHTTP)
		})
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// JWT creates the middleware that parses a JWT encoded token
func JWT(expectedSignatureAlgorithm jwt.SigningMethod) *JWTMiddleware {
	return New(Options{
		Debug:               false,
		CredentialsOptional: false,
		UserProperty:        userPropertyName,
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			if privateKey == nil {
				var err error
				privateKey, err = readPrivateKey()
				if err != nil {
					panic(err)
				}
			}
			return privateKey, nil
		},
		SigningMethod: expectedSignatureAlgorithm,
	})
}

// readPrivateKey will load the keys/sample-key file into the
// global privateKey variable
func readPrivateKey() ([]byte, error) {
	privateKey, e := os.ReadFile("keys/sample-key")
	return privateKey, e
}

// indexHandler will return an empty 200 OK response
func indexHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// protectedHandler will return the content of the "foo" encoded data
// in the token as json -> {"text":"bar"}
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	// retrieve the token from the context (Gorilla context lib)
	u := r.Context().Value(userPropertyName)
	user := u.(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	respondJson(claims["foo"].(string), w)
}

// Response quick n' dirty Response struct to be encoded as json
type Response struct {
	Text string `json:"text"`
}

// respondJson will take an string to write through the writer as json
func respondJson(text string, w http.ResponseWriter) {
	response := Response{text}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(jsonResponse)
}
