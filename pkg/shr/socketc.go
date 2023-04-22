package shr

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

func (s *Shr) handleLocalRequest(requestPath string) ([]byte, string, error) {
	l := log.WithFields(log.Fields{
		"action": "handleLocalRequest",
		"path":   requestPath,
	})
	l.Debug("start")
	var contentType string
	if requestPath == "" {
		l.Error("requestPath is nil")
		return nil, contentType, errors.New("data is nil")
	}
	c := &http.Client{}
	proto := "http"
	if s.TLS != nil {
		proto = "https"
		if s.TLS.CA == nil || *s.TLS.CA == "" {
			return nil, contentType, errors.New("tls.ca is required")
		}
		if s.TLS.Cert == nil || *s.TLS.Cert == "" {
			return nil, contentType, errors.New("tls.cert is required")
		}
		if s.TLS.Key == nil || *s.TLS.Key == "" {
			return nil, contentType, errors.New("tls.key is required")
		}
		if s.TLS != nil {
			tlsConfig := &tls.Config{}
			if s.TLS.CA != nil && *s.TLS.CA != "" {
				// add ca cert to client
				caCert, err := os.ReadFile(*s.TLS.CA)
				if err != nil {
					return nil, contentType, err
				}
				caCertPool := x509.NewCertPool()
				caCertPool.AppendCertsFromPEM(caCert)
				tlsConfig.RootCAs = caCertPool
			}
			if s.TLS.Cert != nil && *s.TLS.Cert != "" && s.TLS.Key != nil && *s.TLS.Key != "" {
				// add client cert to client
				cert, err := tls.LoadX509KeyPair(*s.TLS.Cert, *s.TLS.Key)
				if err != nil {
					return nil, contentType, err
				}
				tlsConfig.Certificates = []tls.Certificate{cert}
			}
			c.Transport = &http.Transport{
				TLSClientConfig: tlsConfig,
			}
		}
	}
	u := url.URL{
		Scheme: proto,
		Host:   *s.Addr + ":" + "8080",
		Path:   requestPath,
	}
	l.Debug("u: ", u)
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		l.WithError(err).Error("Failed to create request")
		return nil, contentType, err
	}
	resp, err := c.Do(req)
	if err != nil {
		l.WithError(err).Error("Failed to do request")
		return nil, contentType, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		l.Error("Failed to get 200 response")
		return nil, contentType, errors.New("failed to get 200 response")
	}
	bd, err := io.ReadAll(resp.Body)
	if err != nil {
		l.WithError(err).Error("failed to read response body")
		return nil, contentType, err
	}
	return bd, contentType, nil
}

func (s *Shr) handleSocketRequest(sra any) error {
	l := log.WithFields(log.Fields{
		"action": "handleSocketRequest",
	})
	l.Debug("start")
	jd, err := json.Marshal(sra)
	if err != nil {
		l.WithError(err).Error("Failed to marshal data")
		return err
	}
	sr := &socketRequest{}
	if err := json.Unmarshal(jd, sr); err != nil {
		l.WithError(err).Error("Failed to unmarshal data")
		return err
	}
	if sr.Path == "" {
		l.Error("requestPath is nil")
		return errors.New("data is nil")
	}
	l.Debug("requestPath: ", sr.Path)
	resp, contentType, err := s.handleLocalRequest(sr.Path)
	if err != nil {
		l.WithError(err).Error("Failed to handle local request")
		sres := &socketResponse{
			ID:          sr.ID,
			Status:      500,
			Body:        []byte(err.Error()),
			ContentType: contentType,
		}
		if err := s.writeSocketMessage("response", sres); err != nil {
			l.WithError(err).Error("Failed to write socket message")
			return err
		}
		return err
	}
	sres := &socketResponse{
		ID:          sr.ID,
		Status:      200,
		Body:        resp,
		ContentType: contentType,
	}
	if err := s.writeSocketMessage("response", sres); err != nil {
		l.WithError(err).Error("Failed to write socket message")
		return err
	}
	return nil
}

func (s *Shr) handleRelaySocketMessage(msg *SocketMessage) error {
	l := log.WithFields(log.Fields{
		"action": "handleRelaySocketMessage",
	})
	l.Debug("start")
	if msg == nil {
		l.Error("msg is nil")
		return errors.New("msg is nil")
	}
	switch msg.Type {
	case "pong":
		l.Debug("handle pong")
	case "register_shr:success":
		l.Debug("handle register_shr:success")
	case "register_shr:failure":
		l.Debug("handle register_shr:failure")
	case "request:path":
		l.Debug("handle request")
		if err := s.handleSocketRequest(msg.Data); err != nil {
			l.WithError(err).Error("Failed to handle socket request")
			return err
		}
	default:
		l.Error("unknown message type: ", msg.Type)
	}
	return nil
}

func (s *Shr) registerSocketWithRelay() error {
	l := log.WithFields(log.Fields{
		"action": "registerSocketWithRelay",
	})
	l.Debug("start")
	if s.Relay.Addr == nil {
		l.Error("addr is nil")
		return errors.New("addr is nil")
	}
	sm := &SocketMessage{
		Type: "register_shr",
		Data: s,
	}
	err := s.socketClient.WriteJSON(sm)
	if err != nil {
		l.WithError(err).Error("Failed to write message to socket")
		return err
	}
	return nil
}

func (s *Shr) relayAddrToSocketAddr() string {
	l := log.WithFields(log.Fields{
		"action": "relayAddrToSocketAddr",
	})
	l.Debug("start")
	if s.Relay.Addr == nil {
		l.Error("addr is nil")
		return ""
	}
	u, err := url.Parse(*s.Relay.Addr)
	if err != nil {
		l.WithError(err).Error("Failed to parse relay addr")
		return ""
	}
	if u.Scheme == "http" {
		u.Scheme = "ws"
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	}
	// add /_shr/ws path
	u.Path = "/_shr/ws"
	sa := u.String()
	l.Debug("sa: ", sa)
	return sa
}

func (s *Shr) openWsClient() error {
	l := log.WithFields(log.Fields{
		"action": "openWsClient",
	})
	l.Debug("start")
	var err error
	// default dialer
	dialer := websocket.DefaultDialer
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
		dialer.TLSClientConfig = tlsConfig
	}
	// check the tls config of our dialer
	s.socketClient, _, err = dialer.Dial(s.relayAddrToSocketAddr(), nil)
	// default dialer
	if err != nil {
		l.WithError(err).Error("Failed to connect to socket")
		return err
	}
	return nil
}

func (s *Shr) wsClient(done chan struct{}) {
	l := log.WithFields(log.Fields{
		"package": "shr",
		"fn":      "wsClient",
	})
	l.Debug("Initializing socket")

	//defer s.socketClient.Close()
	// socket will get closed when the done channel is closed or when interrupted
	l.Debug("Connected to socket")
	if err := s.openWsClient(); err != nil {
		l.WithError(err).Error("Failed to open ws client")
		return
	}
	go func() {
		defer close(done)
		for {
			_, message, err := s.socketClient.ReadMessage()
			if err != nil {
				l.WithError(err).Debug("Failed to read message from socket")
				// if the socket was closed by the remote, try to reconnect up to 5 times
				if websocket.IsCloseError(err, websocket.CloseAbnormalClosure, websocket.CloseGoingAway, websocket.CloseServiceRestart) {
					l.Error("Socket was closed by remote")
					// TODO: gracefully reconnect. for now, just exit
					done <- struct{}{}
				}
				return
			}
			msg, err := parseWSMessage(message)
			if err != nil {
				l.WithError(err).Error("Failed to parse message from socket")
				return
			}
			go func() {
				err = s.handleRelaySocketMessage(msg)
				if err != nil {
					l.WithError(err).Error("Failed to handle message from socket")
					return
				}
			}()
		}
	}()

	if err := s.registerSocketWithRelay(); err != nil {
		l.WithError(err).Error("Failed to register socket with relay")
		return
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	select {
	case <-done:
		l.Debug("Done received, closing socket")
		err := s.socketClient.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		if err != nil {
			l.WithError(err).Error("Failed to write close message to socket")
			return
		}
		l.Debug("Socket closed")
		return
	case <-interrupt:
		l.Debug("Interrupt received, closing socket")
		// Cleanly close the connection by sending a close message and then
		// waiting (with timeout) for the server to close the connection.
		err := s.socketClient.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		if err != nil {
			l.WithError(err).Error("Failed to write close message to socket")
			return
		}
		l.Debug("Socket closed")
		return
	}
}
