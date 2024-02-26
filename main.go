package main

import (
	"context"
	_ "embed"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

//go:embed uri_blogs.txt
var uriBlogs string

//go:embed uri_projects.txt
var uriProjects string

//go:embed uri_presentations.txt
var uriPresentations string

type urlRedirectors struct {
	uris       []string
	target     string
	trimPrefix string
}

var log = logrus.New()

// TODO
// * log 404s
func setupRoutes(router *http.ServeMux) {
	router.Handle("/", http.FileServer(http.Dir("./static")))

	redirectors := []urlRedirectors{
		{
			uris:   strings.Split(uriBlogs, "\n"),
			target: "https://blog.gavinmogan.com",
		},
		{
			uris:       strings.Split(uriProjects, "\n"),
			target:     "https://apps.gavinmogan.com",
			trimPrefix: "/projects",
		},
	}

	for _, redirector := range redirectors {
		for _, uri := range redirector.uris {
			if len(uri) == 0 {
				continue
			}
			uri = filepath.Clean(uri)
			router.Handle(uri, http.RedirectHandler(
				redirector.target+strings.TrimPrefix(uri, redirector.trimPrefix),
				http.StatusMovedPermanently,
			))
			router.Handle(uri+"/", http.RedirectHandler(
				redirector.target+strings.TrimPrefix(uri, redirector.trimPrefix),
				http.StatusMovedPermanently,
			))
		}
	}
}

func main() {
	var listenAddr string
	flag.StringVar(&listenAddr, "listen-addr", ":8090", "server listen address")
	flag.Parse()

	router := http.NewServeMux()
	setupRoutes(router)

	log.Println("Server is starting...")

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      WithLogging(router),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	go func() {
		<-quit
		log.Println("Server is shutting down...")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		server.SetKeepAlivesEnabled(false)
		if err := server.Shutdown(ctx); err != nil {
			log.Fatalf("Could not gracefully shutdown the server: %v\n", err)
		}
		close(done)
	}()

	log.Println("Server is ready to handle requests at", listenAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Could not listen on %s: %v\n", listenAddr, err)
	}

	<-done
	log.Println("Server stopped")
}

func logging(log *logrus.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			uri := r.RequestURI
			method := r.Method

			// log request details
			defer func() {
				duration := time.Since(start)
				log.WithFields(logrus.Fields{
					"uri":      uri,
					"method":   method,
					"duration": duration,
				}).Println("Request")
			}()
			next.ServeHTTP(w, r)
		})
	}
}

type (
	// struct for holding response details
	responseData struct {
		status int
		size   int
	}

	// our http.ResponseWriter implementation
	loggingResponseWriter struct {
		http.ResponseWriter // compose original http.ResponseWriter
		responseData        *responseData
	}
)

func (r *loggingResponseWriter) Write(b []byte) (int, error) {
	size, err := r.ResponseWriter.Write(b) // write response using original http.ResponseWriter
	r.responseData.size += size            // capture size
	return size, err
}

func (r *loggingResponseWriter) WriteHeader(statusCode int) {
	r.ResponseWriter.WriteHeader(statusCode) // write status code using original http.ResponseWriter
	r.responseData.status = statusCode       // capture status code
}

func WithLogging(h http.Handler) http.Handler {
	loggingFn := func(rw http.ResponseWriter, req *http.Request) {
		start := time.Now()

		responseData := &responseData{
			status: 0,
			size:   0,
		}
		lrw := loggingResponseWriter{
			ResponseWriter: rw, // compose original http.ResponseWriter
			responseData:   responseData,
		}
		h.ServeHTTP(&lrw, req) // inject our implementation of http.ResponseWriter

		duration := time.Since(start)

		logrus.WithFields(logrus.Fields{
			"uri":      req.RequestURI,
			"method":   req.Method,
			"status":   responseData.status,
			"duration": duration,
			"size":     responseData.size,
		}).Info("request completed")
	}
	return http.HandlerFunc(loggingFn)
}
