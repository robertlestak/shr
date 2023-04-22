package shr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

type TLSConfig struct {
	CA         *string `yaml:"ca" json:"ca"`
	Cert       *string `yaml:"cert" json:"cert"`
	Key        *string `yaml:"key" json:"key"`
	ClientAuth *bool   `yaml:"client_auth" json:"client_auth"`
}

type RelayConfig struct {
	Addr       *string `yaml:"addr" json:"addr"`
	SocketMode *bool   `yaml:"socket_mode" json:"socket_mode"`
	AuthKey    *string `yaml:"auth_key" json:"auth_key"`
	Key        *string `yaml:"key" json:"key"`
}

type Shr struct {
	ID        *string      `yaml:"id" json:"id"`
	Path      *string      `yaml:"path" json:"path"`
	Addr      *string      `yaml:"addr" json:"addr"`
	Advertise *string      `yaml:"advertise" json:"advertise"`
	Port      *int         `yaml:"port" json:"port"`
	TLS       *TLSConfig   `yaml:"tls" json:"tls"`
	Relay     *RelayConfig `yaml:"relay" json:"relay"`

	socketClient *websocket.Conn
}

func newID() *string {
	id := uuid.New().String()
	return &id
}

func (s *Shr) New() error {
	l := log.WithFields(log.Fields{
		"func": "New",
	})
	l.Debug("Creating new shr")
	if s.ID == nil || *s.ID == "" {
		s.ID = newID()
	}
	if s.Path == nil {
		return errors.New("path is required")
	}
	if _, err := os.Stat(*s.Path); os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *Shr) handler(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"func": "handler",
	})
	l.WithFields(log.Fields{
		"method": r.Method,
		"path":   r.URL.Path,
	}).Debug("shr request")
	// ensure path is prefixed with id
	if !strings.HasPrefix(r.URL.Path, "/"+*s.ID) {
		l.WithFields(log.Fields{
			"method": r.Method,
			"path":   r.URL.Path,
		}).Debug("shr request not found")
		// no content
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// redirect /shr to /shr/
	if r.URL.Path == "/"+*s.ID {
		http.Redirect(w, r, "/"+*s.ID+"/", http.StatusFound)
		return
	}
	// if path is a file, serve it
	// if path is a directory, serve dir
	stat, err := os.Stat(*s.Path)
	if err != nil {
		l.WithFields(log.Fields{
			"method": r.Method,
			"path":   r.URL.Path,
		}).Debug("shr request not found")
		http.NotFound(w, r)
		return
	}
	if stat.IsDir() {
		l.WithFields(log.Fields{
			"method": r.Method,
			"path":   r.URL.Path,
		}).Debug("shr request directory")
		// strip path prefix
		http.StripPrefix("/"+*s.ID, http.FileServer(http.Dir(*s.Path))).ServeHTTP(w, r)
		return
	} else {
		l.WithFields(log.Fields{
			"method": r.Method,
			"path":   r.URL.Path,
		}).Debug("shr request file")
		http.ServeFile(w, r, *s.Path)
		return
	}
}

func (s *Shr) Start() error {
	l := log.WithFields(log.Fields{
		"func": "Start",
	})
	l.Debug("Starting shr")
	if s.ID == nil {
		return errors.New("id is required")
	}
	http.HandleFunc("/", s.handler)
	l.WithFields(log.Fields{
		"id":   *s.ID,
		"path": *s.Path,
	}).Debug("shr started")
	done := make(chan bool)
	if s.TLS != nil {
		if s.TLS.CA == nil || *s.TLS.CA == "" {
			return errors.New("tls.ca is required")
		}
		if s.TLS.Cert == nil || *s.TLS.Cert == "" {
			return errors.New("tls.cert is required")
		}
		if s.TLS.Key == nil || *s.TLS.Key == "" {
			return errors.New("tls.key is required")
		}
		l.WithFields(log.Fields{
			"addr": *s.Addr,
			"port": *s.Port,
		}).Debug("shr started with tls")
		caCert, err := os.ReadFile(*s.TLS.CA)
		if err != nil {
			return err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig := &tls.Config{
			ClientCAs: caCertPool,
		}
		if s.TLS.ClientAuth != nil && *s.TLS.ClientAuth {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
		server := &http.Server{
			Addr:      fmt.Sprintf("%s:%d", *s.Addr, *s.Port),
			TLSConfig: tlsConfig,
		}
		fmt.Printf("shr started with tls: https://%s:%d/%s/\n", *s.Addr, *s.Port, *s.ID)
		go func() {
			if err := server.ListenAndServeTLS(*s.TLS.Cert, *s.TLS.Key); err != nil {
				log.Fatal(err)
			}
			done <- true
		}()
	} else {
		l.WithFields(log.Fields{
			"addr": *s.Addr,
			"port": *s.Port,
		}).Debug("shr started without tls")
		fmt.Printf("shr started without tls: http://%s:%d/%s/\n", *s.Addr, *s.Port, *s.ID)
		go func() {
			if err := http.ListenAndServe(fmt.Sprintf("%s:%d", *s.Addr, *s.Port), nil); err != nil {
				log.Fatal(err)
			}
			done <- true
		}()
	}
	if s.Relay.Addr != nil && *s.Relay.Addr != "" {
		if err := s.registerWithRelay(); err != nil {
			log.Fatal(err)
		}
		if s.Relay.SocketMode != nil && *s.Relay.SocketMode {
			done := make(chan struct{})
			go s.wsClient(done)
			l.Debug("shr started with relay (socket mode)")
			<-done
			l.Debug("shr stopped with relay (socket mode)")
		}
	}
	<-done
	return nil
}

func (s *Shr) httpProxy(w http.ResponseWriter, r *http.Request) error {
	l := log.WithFields(log.Fields{
		"func": "httpProxy",
	})
	l.Debug("shr http proxy")
	// proxy request to shr
	proto := "http"
	if s.TLS != nil {
		proto = "https"
	}
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: proto,
		Host:   fmt.Sprintf("%s:%d", *s.Advertise, *s.Port),
	})
	if s.TLS != nil {
		tlsConfig := &tls.Config{}
		if s.TLS.CA != nil && *s.TLS.CA != "" {
			caCert, err := os.ReadFile(*s.TLS.CA)
			if err != nil {
				return err
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.RootCAs = caCertPool
		}
		if s.TLS.Cert != nil && *s.TLS.Cert != "" {
			cert, err := tls.LoadX509KeyPair(*s.TLS.Cert, *s.TLS.Key)
			if err != nil {
				return err
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
		}
		proxy.Transport = transport
	}
	proxy.ServeHTTP(w, r)
	return nil
}

func (s *Shr) wsProxy(w http.ResponseWriter, r *http.Request) error {
	l := log.WithFields(log.Fields{
		"func": "wsProxy",
	})
	l.Debug("shr ws proxy")
	requestPath := r.URL.Path
	requestId := r.Header.Get("X-Request-Id")
	if requestId == "" {
		requestId = uuid.New().String()
	}
	resp, contentType, err := s.requestThroughSocket(r.Context(), requestId, requestPath)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", contentType)
	w.Write(resp)
	return nil
}

type socketRequest struct {
	ID   string `json:"id"`
	Path string `json:"path"`
}

type socketResponse struct {
	ID          string `json:"id"`
	Status      int    `json:"status"`
	Body        []byte `json:"body"`
	ContentType string `json:"content_type"`
}

func (s *Shr) getSocketResponse(ctx context.Context, id string) (socketResponse, error) {
	l := log.WithFields(log.Fields{
		"func": "getSocketResponse",
		"id":   id,
	})
	l.Debug("shr get socket response")
	// exit when context is done
	var sr socketResponse
	for {
		select {
		case <-ctx.Done():
			return sr, ctx.Err()
		default:
		}
		tsr, ok := socketResponses[id]
		if ok {
			sr = tsr
			delete(socketResponses, id)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return sr, nil
}

func (s *Shr) requestThroughSocket(ctx context.Context, requestId string, requestPath string) ([]byte, string, error) {
	l := log.WithFields(log.Fields{
		"func": "requestThroughSocket",
	})
	l.WithFields(log.Fields{
		"path": requestPath,
	}).Debug("shr request through proxy")
	var contentType string
	sr := socketRequest{
		ID:   requestId,
		Path: requestPath,
	}
	if err := s.writeSocketMessage("request:path", sr); err != nil {
		l.WithFields(log.Fields{
			"error": err,
		}).Error("shr ws proxy write socket message")
		return nil, contentType, err
	}
	sresp, err := s.getSocketResponse(ctx, requestId)
	if err != nil {
		l.WithFields(log.Fields{
			"error": err,
		}).Error("shr ws proxy get socket response")
		return nil, contentType, err
	}
	if sresp.Status != 200 {
		l.WithFields(log.Fields{
			"status": sresp.Status,
		}).Error("shr ws proxy get socket response status")
		return nil, contentType, errors.New("error processing request")
	}
	return sresp.Body, sresp.ContentType, nil
}

func (s *Shr) RelayRequest(w http.ResponseWriter, r *http.Request) error {
	l := log.WithFields(log.Fields{
		"func": "RelayRequest",
	})
	l.WithFields(log.Fields{
		"method":     r.Method,
		"path":       r.URL.Path,
		"socketMode": *s.Relay.SocketMode,
	}).Debug("shr relay request")
	if s.Advertise == nil {
		return errors.New("addr is required")
	}
	if s.Port == nil {
		return errors.New("port is required")
	}
	if s.Relay.SocketMode != nil && *s.Relay.SocketMode {
		return s.wsProxy(w, r)
	} else {
		return s.httpProxy(w, r)
	}
}
