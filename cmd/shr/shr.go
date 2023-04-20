package main

import (
	"errors"
	"flag"
	"net"
	"os"

	netroute "github.com/libp2p/go-netroute"
	"github.com/robertlestak/shr/pkg/shr"
	log "github.com/sirupsen/logrus"
)

var (
	Version = "dev"
)

func init() {
	ll, err := log.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		ll = log.InfoLevel
	}
	log.SetLevel(ll)
}

func main() {
	shrFlags := flag.NewFlagSet("shr", flag.ExitOnError)
	logLevel := shrFlags.String("log-level", log.GetLevel().String(), "Log level")
	addr := shrFlags.String("addr", "", "shr address")
	advertise := shrFlags.String("advertise", "", "shr advertise address")
	port := shrFlags.Int("port", 8080, "shr port")
	tlsCA := shrFlags.String("tls-ca", "", "shr TLS CA")
	tlsCert := shrFlags.String("tls-crt", "", "shr TLS certificate")
	tlsKey := shrFlags.String("tls-key", "", "shr TLS key")
	id := shrFlags.String("id", "", "shr ID")
	relayAddr := shrFlags.String("relay-addr", "", "shr relay address")
	relayKey := shrFlags.String("relay-key", "", "shr relay key")
	relayMode := shrFlags.Bool("relay", false, "shr relay mode")
	version := shrFlags.Bool("version", false, "shr version")
	shrFlags.Parse(os.Args[1:])
	ll, err := log.ParseLevel(*logLevel)
	if err != nil {
		log.Fatal(err)
	}
	log.SetLevel(ll)
	if *version {
		log.WithField("version", Version).Info("shr version")
		return
	}
	var tc *shr.TLSConfig
	if *tlsCA != "" || *tlsCert != "" || *tlsKey != "" {
		tc = &shr.TLSConfig{
			CA:   tlsCA,
			Cert: tlsCert,
			Key:  tlsKey,
		}
	}
	if advertise == nil || *advertise == "" {
		// set addr to default
		var intIp string
		r, err := netroute.New()
		if err != nil {
			log.Fatal(err)
		}
		_, _, src, err := r.Route(net.IPv4(0, 0, 0, 0))
		if err != nil {
			log.Fatal(err)
		}
		intIp = src.String()
		if intIp == "" {
			log.Fatal(errors.New("unable to determine default interface"))
		}
		advertise = &intIp
	}
	if addr == nil || *addr == "" {
		// set addr to default
		addr = advertise
	}
	s := &shr.Shr{
		ID:           id,
		Addr:         addr,
		Advertise:    advertise,
		Port:         port,
		RelayAddr:    relayAddr,
		RelayAuthKey: relayKey,
		TLS:          tc,
	}
	if *relayMode {
		if err := s.StartRelay(); err != nil {
			log.Fatal(err)
		}
		return
	}
	path := shrFlags.Arg(0)
	if path == "" {
		log.Fatal("path is required")
	}
	s.Path = &path
	if err := s.New(); err != nil {
		log.Fatal(err)
	}
	log.WithFields(log.Fields{
		"id":   *s.ID,
		"path": *s.Path,
	}).Debug("shr created")
	if err := s.Start(); err != nil {
		log.Fatal(err)
	}
}
