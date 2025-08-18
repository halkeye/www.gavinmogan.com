package main

import (
	"context"
	"embed"
	"flag"
	"io/fs"
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

//go:embed static/**
var staticDir embed.FS

type urlRedirectors struct {
	uris       []string
	target     string
	trimPrefix string
}

var log = logrus.New()

func main() {
	var listenAddr string
	var httpsOnly bool
	flag.StringVar(&listenAddr, "listen-addr", ":8090", "server listen address")
	flag.BoolVar(&httpsOnly, "https-only", false, "dont allow http request")
	flag.Parse()

	router := http.NewServeMux()
	setupRoutes(router, httpsOnly)

	log.Println("Server is starting...")

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      withLogging(router),
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

// struct for holding response details
type responseData struct {
	status int
	size   int
}

// our http.ResponseWriter implementation
type loggingResponseWriter struct {
	http.ResponseWriter // compose original http.ResponseWriter
	responseData        *responseData
}

func (r *loggingResponseWriter) Write(b []byte) (int, error) {
	size, err := r.ResponseWriter.Write(b) // write response using original http.ResponseWriter
	r.responseData.size += size            // capture size
	return size, err
}

func (r *loggingResponseWriter) WriteHeader(statusCode int) {
	r.ResponseWriter.WriteHeader(statusCode) // write status code using original http.ResponseWriter
	r.responseData.status = statusCode       // capture status code
}

func withLogging(h http.Handler) http.Handler {
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

		if !strings.HasPrefix(req.RequestURI, "/page-data/") && !strings.HasPrefix(req.RequestURI, "/favicon.ico") {
			logrus.WithFields(logrus.Fields{
				"uri":       req.RequestURI,
				"method":    req.Method,
				"useragent": req.Header.Get("User-Agent"),
				"host":      req.Header.Get("Host"),
				"status":    responseData.status,
				"duration":  duration,
				"size":      responseData.size,
			}).Info("request completed")
		}
	}
	return http.HandlerFunc(loggingFn)
}

func getAllFilenames(efs fs.FS) (files []string, err error) {
	if err := fs.WalkDir(efs, ".", func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}

		files = append(files, path)

		return nil
	}); err != nil {
		return nil, err
	}

	return files, nil
}

func setupRoutes(router *http.ServeMux, httpsOnly bool) {
	sub, err := fs.Sub(staticDir, "static")
	if err != nil {
		panic(err)
	}

	files, _ := getAllFilenames(sub)
	logrus.WithFields(logrus.Fields{"files": files}).Info("files")

	router.Handle("/", withFrameOptions(withContentTypeOptions(withReferralPolicy(withCSP(httpsOnly, withCors(http.FileServer(http.FS(sub))))))))

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
		{
			uris:       strings.Split(uriPresentations, "\n"),
			target:     "https://presentations.gavinmogan.com",
			trimPrefix: "/presentations",
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

func withCors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Access-Control-Allow-Origin", "*")
		h.ServeHTTP(rw, req)
	})
}

func withCSP(httpsOnly bool, h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		csp := []string{
			"default-src 'none'",
			"script-src 'self' 'p.g4v.dev' 'u.g4v.dev' 'sha256-ZswfTY7H35rbv8WC7NXBoiC7WNu86vSzCDChNWwZZDM=' 'sha256-ZswfTY7H35rbv8WC7NXBoiC7WNu86vSzCDChNWwZZDM='",
			"script-src-elem 'self' 'p.g4v.dev' 'u.g4v.dev' 'sha256-ZswfTY7H35rbv8WC7NXBoiC7WNu86vSzCDChNWwZZDM=' 'sha256-ZswfTY7H35rbv8WC7NXBoiC7WNu86vSzCDChNWwZZDM='",
			// prevents <button id="btn" onclick="doSomething()"></button>
			"script-src-attr 'none'",
			"style-src 'self'",
			"style-src-elem 'self'",
			"img-src 'self'",
			"font-src 'self'",
			"connect-src 'none'",
			"media-src 'none'",
			"object-src 'none'",
			"prefetch-src 'self'",
			"child-src 'none'",
			"frame-src 'none'",
			"worker-src 'none'",
			"frame-ancestors 'none'",
			"form-action 'none'",
			"disown-opener",
		}
		if httpsOnly {
			csp = append(csp, "upgrade-insecure-requests")
			csp = append(csp, "block-all-mixed-content")
		}
		rw.Header().Set("Content-Security-Policy", strings.Join(csp, "; "))
		h.ServeHTTP(rw, req)
	})
}

func withReferralPolicy(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(rw, req)
	})
}

func withContentTypeOptions(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("X-Content-Type-Options", "nosniff")
		h.ServeHTTP(rw, req)
	})
}

func withFrameOptions(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("X-Frame-Options", "DENY")
		h.ServeHTTP(rw, req)
	})
}
