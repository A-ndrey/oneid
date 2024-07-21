package middleware

import (
	"net/http"
	"strings"
	"testing"
)

type FakeWriter struct {
	http.ResponseWriter
	Data *strings.Builder
}

func (f *FakeWriter) Write(p []byte) (int, error) {
	return f.Data.Write(p)
}

func TestAttach(t *testing.T) {
	createFunc := func(id string) Link {
		return func(handler http.Handler) http.Handler {
			return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Write([]byte(id))
				handler.ServeHTTP(writer, request)
				writer.Write([]byte(id))
			})
		}
	}

	fw := FakeWriter{Data: &strings.Builder{}}
	fh := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("fh"))
	})

	h := Attach(fh, createFunc("1"), createFunc("2"), createFunc("3"))

	h.ServeHTTP(&fw, nil)

	expected := "123fh321"
	if actual := fw.Data.String(); actual != expected {
		t.Errorf("expected: %s, but actual: %s", expected, actual)
	}
}
