package middleware

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Middleware func(handler http.Handler) http.Handler
type key int

const (
	CTXKeyPenmanshipEncryption key = 0
)

func MakeAuthzMiddleware(baseUrl string) Middleware {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			client := http.Client{
				Timeout: 10 * time.Second,
			}

			url := fmt.Sprintf("%s/authz", baseUrl)

			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(err.Error()))
			}

			req.Header.Set("X-CSRF-TOKEN", r.Header.Get("X-CSRF-TOKEN"))
			req.Header.Set("Cookie", r.Header.Get("Cookie"))

			res, err := client.Do(req)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(err.Error()))
			}

			if res.StatusCode == http.StatusOK {
				handler.ServeHTTP(w, r)
			}
		})
	}
}

func MakePenmanshipDataMiddleware(baseUrl string) Middleware {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			client := http.Client{
				Timeout: 10 * time.Second,
			}

			url := fmt.Sprintf("%s/encryption", baseUrl)

			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
			}

			req.Header.Set("X-CSRF-TOKEN", r.Header.Get("X-CSRF-TOKEN"))
			req.Header.Set("Cookie", r.Header.Get("Cookie"))

			res, err := client.Do(req)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(err.Error()))
			}

			if res.StatusCode == http.StatusOK {
				data, err := io.ReadAll(res.Body)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(err.Error()))
				}

				r = r.WithContext(context.WithValue(r.Context(), CTXKeyPenmanshipEncryption, string(data)))

				handler.ServeHTTP(w, r)
			}
		})
	}
}
