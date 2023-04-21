package shr

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

type TLSConfig struct {
	CA   *string `yaml:"ca" json:"ca"`
	Cert *string `yaml:"cert" json:"cert"`
	Key  *string `yaml:"key" json:"key"`
}

type RelayConfig struct {
	Addr    *string `yaml:"addr" json:"addr"`
	AuthKey *string `yaml:"auth_key" json:"auth_key"`
	Key     *string `yaml:"key" json:"key"`
}

type Shr struct {
	ID        *string      `yaml:"id" json:"id"`
	Path      *string      `yaml:"path" json:"path"`
	Addr      *string      `yaml:"addr" json:"addr"`
	Advertise *string      `yaml:"advertise" json:"advertise"`
	Port      *int         `yaml:"port" json:"port"`
	TLS       *TLSConfig   `yaml:"tls" json:"tls"`
	Relay     *RelayConfig `yaml:"relay" json:"relay"`
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
		http.NotFound(w, r)
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
			ClientCAs:  caCertPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
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
		}()
	}
	if s.Relay.Addr != nil && *s.Relay.Addr != "" {
		go func() {
			if err := s.registerWithRelay(); err != nil {
				log.Fatal(err)
			}
		}()
	}
	select {}
}

func (s *Shr) RelayRequest(w http.ResponseWriter, r *http.Request) error {
	l := log.WithFields(log.Fields{
		"func": "RelayRequest",
	})
	l.WithFields(log.Fields{
		"method": r.Method,
		"path":   r.URL.Path,
	}).Debug("shr relay request")
	if s.Advertise == nil {
		return errors.New("addr is required")
	}
	if s.Port == nil {
		return errors.New("port is required")
	}
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
