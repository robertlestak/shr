package shr

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

var (
	Relays = map[string]*Shr{}
)

func (s *Shr) healthcheckHandler(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"func": "healthcheckHandler",
	})
	l.WithFields(log.Fields{
		"method": r.Method,
		"path":   r.URL.Path,
	}).Debug("shr healthcheck request")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Write([]byte("ok"))
}

func (s *Shr) registerRelay(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"func": "registerRelay",
	})
	l.WithFields(log.Fields{
		"method": r.Method,
		"path":   r.URL.Path,
	}).Debug("shr relay request")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var shr Shr
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&shr); err != nil {
		l.WithFields(log.Fields{
			"err": err,
		}).Error("shr relay request failed")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if s.RelayAuthKey != nil && shr.RelayAuthKey != nil && *s.RelayAuthKey != *shr.RelayAuthKey {
		l.Error("shr relay request failed")
		http.Error(w, "invalid relay key", http.StatusUnauthorized)
		return
	}
	if shr.ID == nil || *shr.ID == "" {
		l.Error("shr relay request failed")
		http.Error(w, "shr id is required", http.StatusBadRequest)
		return
	}
	if shr.Advertise == nil || *shr.Advertise == "" {
		l.Error("shr relay request failed")
		http.Error(w, "shr addr is required", http.StatusBadRequest)
		return
	}
	if shr.Port == nil || *shr.Port == 0 {
		l.Error("shr relay request failed")
		http.Error(w, "shr port is required", http.StatusBadRequest)
		return
	}
	k := uuid.New().String()
	shr.RelayKey = &k
	Relays[*shr.ID] = &shr
	l.WithFields(log.Fields{
		"shr": shr,
	}).Debug("shr relay register succeeded")
	w.Write([]byte(k))
}

func RemoveRelay(id string) {
	l := log.WithFields(log.Fields{
		"func": "RemoveRelay",
	})
	l.WithFields(log.Fields{
		"id": id,
	}).Debug("Removing shr relay")
	delete(Relays, id)
}

func (s *Shr) unregisterRelay(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"func": "unregisterRelay",
	})
	l.WithFields(log.Fields{
		"method": r.Method,
		"path":   r.URL.Path,
	}).Debug("shr relay request")
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// url will be in format:
	// /_shr/unregister/<shr-id>/<relay-key>
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 5 {
		l.Error("shr relay request failed")
		http.Error(w, "invalid url", http.StatusBadRequest)
		return
	}
	id := parts[3]
	key := parts[4]
	shr, ok := Relays[id]
	if !ok {
		l.Error("shr relay request failed")
		http.Error(w, "shr not found", http.StatusNotFound)
		return
	}
	if shr.RelayKey == nil || *shr.RelayKey != key {
		l.Error("shr relay request failed")
		http.Error(w, "invalid relay key", http.StatusUnauthorized)
		return
	}
	RemoveRelay(id)
	l.WithFields(log.Fields{
		"id": id,
	}).Debug("shr relay request succeeded")
	w.WriteHeader(http.StatusOK)
}

func (s *Shr) registerWithRelay() error {
	l := log.WithFields(log.Fields{
		"func": "registerWithRelay",
	})
	l.Debug("Registering with shr relay")
	if s.RelayAddr == nil || *s.RelayAddr == "" {
		return errors.New("shr relay addr is required")
	}
	if s.ID == nil || *s.ID == "" {
		return errors.New("shr id is required")
	}
	if s.Advertise == nil || *s.Advertise == "" {
		return errors.New("shr addr is required")
	}
	if s.Port == nil || *s.Port == 0 {
		return errors.New("shr port is required")
	}
	// trap exit and unregister with relay
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	go func() {
		<-ch
		s.UnregisterWithRelay()
		os.Exit(0)
	}()
	shr := &Shr{
		ID:           s.ID,
		Advertise:    s.Advertise,
		Port:         s.Port,
		TLS:          s.TLS,
		RelayAuthKey: s.RelayAuthKey,
	}
	l.WithFields(log.Fields{
		"adv": *shr.Advertise,
	}).Debug("Registering with shr relay")
	shrJson, err := json.Marshal(shr)
	if err != nil {
		return err
	}
	c := &http.Client{}
	if s.TLS != nil {
		tlsConfig := &tls.Config{}
		if s.TLS.CA != nil && *s.TLS.CA != "" {
			// add ca cert to client
			caCert, err := os.ReadFile(*s.TLS.CA)
			if err != nil {
				return err
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.RootCAs = caCertPool
		}
		if s.TLS.Cert != nil && *s.TLS.Cert != "" && s.TLS.Key != nil && *s.TLS.Key != "" {
			// add client cert to client
			cert, err := tls.LoadX509KeyPair(*s.TLS.Cert, *s.TLS.Key)
			if err != nil {
				return err
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
		c.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}
	u := fmt.Sprintf("%s/_shr/register", *s.RelayAddr)
	resp, err := c.Post(u, "application/json", strings.NewReader(string(shrJson)))
	if err != nil {
		l.WithFields(log.Fields{
			"err": err,
		}).Error("shr relay registration failed")
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		l.WithFields(log.Fields{
			"err": err,
			"bdy": string(body),
		}).Error("shr relay registration failed")
		return err
	}
	if resp.StatusCode != http.StatusOK {
		l.WithFields(log.Fields{
			"statusCode": resp.StatusCode,
			"bdy":        string(body),
		}).Error("shr relay registration failed")
		return errors.New("shr relay registration failed")
	}
	k := string(body)
	s.RelayKey = &k
	l.WithFields(log.Fields{
		"relayKey": *s.RelayKey,
	}).Debug("shr relay registration succeeded")
	fmt.Printf("shr relay started: %s/%s/\n", *s.RelayAddr, *s.ID)
	return nil
}

func (s *Shr) UnregisterWithRelay() error {
	l := log.WithFields(log.Fields{
		"func": "UnregisterWithRelay",
	})
	l.Debug("Unregistering with shr relay")
	if s.RelayAddr == nil || *s.RelayAddr == "" {
		return errors.New("shr relay addr is required")
	}
	if s.ID == nil || *s.ID == "" {
		return errors.New("shr id is required")
	}
	if s.RelayKey == nil || *s.RelayKey == "" {
		return errors.New("shr relay key is required")
	}
	c := &http.Client{}
	if s.TLS != nil {
		tlsConfig := &tls.Config{}
		if s.TLS.CA != nil && *s.TLS.CA != "" {
			// add ca cert to client
			caCert, err := os.ReadFile(*s.TLS.CA)
			if err != nil {
				return err
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.RootCAs = caCertPool
		}
		if s.TLS.Cert != nil && *s.TLS.Cert != "" && s.TLS.Key != nil && *s.TLS.Key != "" {
			// add client cert to client
			cert, err := tls.LoadX509KeyPair(*s.TLS.Cert, *s.TLS.Key)
			if err != nil {
				return err
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
		c.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}
	u := fmt.Sprintf("%s/_shr/unregister/%s/%s", *s.RelayAddr, *s.ID, *s.RelayKey)
	req, err := http.NewRequest(http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("shr relay unregistration failed")
	}
	defer resp.Body.Close()
	l.Debug("shr relay unregistration succeeded")
	return nil
}

func (s *Shr) relayHandler(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"func": "relayHandler",
	})
	l.WithFields(log.Fields{
		"method": r.Method,
		"path":   r.URL.Path,
	}).Debug("shr relay request")
	// url will be in format:
	// /<shr-id>/<path>
	shrId := strings.Split(r.URL.Path, "/")[1]
	if shr, ok := Relays[shrId]; ok {
		l.WithFields(log.Fields{
			"shr": shr,
		}).Debug("shr found")
		if err := shr.RelayRequest(w, r); err != nil {
			l.WithFields(log.Fields{
				"err": err,
			}).Error("shr relay request failed")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		l.WithFields(log.Fields{
			"shr": shrId,
		}).Debug("shr not found")
		http.Error(w, "shr not found", http.StatusNotFound)
		return
	}
}

func (s *Shr) StartRelay() error {
	l := log.WithFields(log.Fields{
		"func": "StartRelay",
	})
	l.Debug("Starting shr relay")
	http.HandleFunc("/_shr/healthz", s.healthcheckHandler)
	http.HandleFunc("/_shr/register", s.registerRelay)
	http.HandleFunc("/_shr/unregister/", s.unregisterRelay)
	http.HandleFunc("/", s.relayHandler)
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
		fmt.Printf("shr relay started with tls: https://%s:%d/\n", *s.Addr, *s.Port)
		if err := server.ListenAndServeTLS(*s.TLS.Cert, *s.TLS.Key); err != nil {
			return err
		}
		return nil
	} else {
		l.WithFields(log.Fields{
			"addr": *s.Addr,
			"port": *s.Port,
		}).Debug("shr started without tls")
		fmt.Printf("shr relay started without tls: http://%s:%d/\n", *s.Addr, *s.Port)
		if err := http.ListenAndServe(fmt.Sprintf("%s:%d", *s.Addr, *s.Port), nil); err != nil {
			return err
		}
	}
	return nil
}
