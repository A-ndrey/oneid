package main

import (
	"errors"
	"log"
	"net/http"
)

var webContent = `
<!DOCTYPE html>
<html lang="en">
<head>
	<title>client-test</title>
</head>
<body>
<a href="http://localhost:8080/?redirect_url=http://localhost:4000/web&token_param=token">auth-web</a>
<a href="http://localhost:8080/?redirect_url=http://localhost:4000/server&token_param=token">auth-server</a>
</body>
</html>
`

func main() {
	http.HandleFunc("/web", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte(webContent))
		writer.Header().Add("Content-Type", "text/html")
	})
	http.HandleFunc("/server", func(writer http.ResponseWriter, request *http.Request) {
		log.Println(request.URL.String())
		writer.WriteHeader(http.StatusAccepted)
	})

	if err := http.ListenAndServe("localhost:4000", nil); err != nil && !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}
