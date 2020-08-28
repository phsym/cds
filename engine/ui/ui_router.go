package ui

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/ovh/cds/engine/api"
	"github.com/ovh/cds/engine/service"
	"github.com/ovh/cds/sdk/log"
)

func (s *Service) initRouter(ctx context.Context) {
	log.Debug("ui> Router initialized")
	r := s.Router
	r.Background = ctx
	r.URL = s.Cfg.URL
	r.SetHeaderFunc = api.DefaultHeaders
	r.PostMiddlewares = append(r.PostMiddlewares, api.TracingPostMiddleware)

	r.Handle(s.Cfg.DeployURL+"/mon/version", nil, r.GET(api.VersionHandler, api.Auth(false)))
	r.Handle(s.Cfg.DeployURL+"/mon/status", nil, r.GET(s.statusHandler, api.Auth(false)))
	r.Handle(s.Cfg.DeployURL+"/mon/metrics", nil, r.GET(service.GetPrometheustMetricsHandler(s), api.Auth(false)))
	r.Handle(s.Cfg.DeployURL+"/mon/metrics/all", nil, r.GET(service.GetMetricsHandler, api.Auth(false)))

	// proxypass
	r.Mux.PathPrefix(s.Cfg.DeployURL + "/cdsapi").Handler(s.getReverseProxy(s.Cfg.DeployURL+"/cdsapi", s.Cfg.API.HTTP.URL, s.Cfg.API.HTTP.Insecure))
	r.Mux.PathPrefix(s.Cfg.DeployURL + "/cdshooks").Handler(s.getReverseProxy(s.Cfg.DeployURL+"/cdshooks", s.Cfg.HooksURL, s.Cfg.API.HTTP.Insecure))

	// serve static UI files
	r.Mux.PathPrefix("/docs").Handler(s.uiServe(http.Dir(s.DocsDir), s.DocsDir))
	r.Mux.PathPrefix("/").Handler(s.uiServe(http.Dir(s.HTMLDir), s.HTMLDir))
}

func (s *Service) getReverseProxy(path, urlRemote string, insecure bool) *httputil.ReverseProxy {
	origin, _ := url.Parse(urlRemote)

	director := func(req *http.Request) {
		reqPath := strings.TrimPrefix(req.URL.Path, path)
		// on proxypass /cdshooks, allow only request on /webhook/ path
		if strings.HasSuffix(path, "/cdshooks") && !strings.HasPrefix(reqPath, "/webhook/") {
			// return 502 bad gateway
			req = &http.Request{} // nolint
		} else {
			req.Header.Add("X-Forwarded-Host", req.Host)
			req.Header.Add("X-Origin-Host", origin.Host)
			req.URL.Scheme = origin.Scheme
			req.URL.Host = origin.Host
			req.URL.Path = origin.Path + reqPath
			req.Host = origin.Host
		}
	}
	// Default transport as defined in std lib, modified with TLSClient config added
	// to set InsecureSkipVerify if needed
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
	}
	return &httputil.ReverseProxy{Director: director, Transport: transport}
}

func (s *Service) uiServe(fs http.FileSystem, dir string) http.Handler {
	fsh := http.FileServer(fs)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dir == s.DocsDir {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/docs")
		} else {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, s.Cfg.DeployURL)
		}
		filePath := path.Clean(r.URL.Path)
		_, err := fs.Open(filePath)
		if os.IsNotExist(err) {
			http.ServeFile(w, r, filepath.Join(dir, "index.html"))
			return
		}
		fsh.ServeHTTP(w, r)
	})
}
