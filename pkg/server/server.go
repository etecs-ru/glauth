package server

import (
	"errors"
	"fmt"
	"plugin"

	"github.com/GeertJohan/yubigo"
	"github.com/etecs-ru/glauth/v2/pkg/config"
	"github.com/etecs-ru/glauth/v2/pkg/handler"
	"github.com/nmcclain/ldap"
	"go.uber.org/zap"
)

type LdapSvc struct {
	log      *zap.Logger
	c        *config.Config
	yubiAuth *yubigo.YubiAuth
	l        *ldap.Server
}

func NewServer(opts ...Option) (*LdapSvc, error) {
	options := newOptions(opts...)

	s := LdapSvc{
		log: options.Logger,
		c:   options.Config,
	}

	var err error

	if len(s.c.YubikeyClientID) > 0 && len(s.c.YubikeySecret) > 0 {
		s.yubiAuth, err = yubigo.NewYubiAuth(s.c.YubikeyClientID, s.c.YubikeySecret)

		if err != nil {
			return nil, errors.New("Yubikey Auth failed")
		}
	}

	var helper handler.Handler

	loh := handler.NewLDAPOpsHelper()

	// instantiate the helper, if any
	if s.c.Helper.Enabled {
		switch s.c.Helper.Datastore {
		case "config":
			helper = handler.NewConfigHandler(
				handler.Logger(s.log),
				handler.Config(s.c),
				handler.YubiAuth(s.yubiAuth),
				handler.LDAPHelper(loh),
			)
		case "plugin":
			plug, err := plugin.Open(s.c.Helper.Plugin)
			if err != nil {
				return nil, errors.New(fmt.Sprintf("Unable to load specified helper plugin: %s", err))
			}
			nph, err := plug.Lookup(s.c.Helper.PluginHandler)
			if err != nil {
				return nil, errors.New("Unable to find 'NewPluginHandler' in loaded helper plugin")
			}
			initFunc, ok := nph.(func(...handler.Option) handler.Handler)

			if !ok {
				return nil, errors.New("Loaded helper plugin lacks a proper NewPluginHandler function")
			}
			// Normally, here, we would somehow have imported our plugin into our
			// handler namespace. Oops?
			helper = initFunc(
				handler.Logger(s.log),
				handler.Config(s.c),
				handler.YubiAuth(s.yubiAuth),
				handler.LDAPHelper(loh),
			)
		default:
			return nil, fmt.Errorf("unsupported helper %s - must be one of 'config', 'plugin'", s.c.Helper.Datastore)
		}
		s.log.Info("Using helper", zap.String("datastore", s.c.Helper.Datastore))
	}

	backendCounter := -1
	allHandlers := handler.HandlerWrapper{Handlers: make([]handler.Handler, 10), Count: &backendCounter}

	// configure the backends
	s.l = ldap.NewServer()
	s.l.EnforceLDAP = true
	for i, backend := range s.c.Backends {
		var h handler.Handler
		switch backend.Datastore {
		case "ldap":
			h = handler.NewLdapHandler(
				handler.Backend(backend),
				handler.Handlers(allHandlers),
				handler.Logger(s.log),
				handler.Helper(helper),
			)
		case "owncloud":
			h = handler.NewOwnCloudHandler(
				handler.Backend(backend),
				handler.Logger(s.log),
			)
		case "config":
			h = handler.NewConfigHandler(
				handler.Backend(backend),
				handler.Logger(s.log),
				handler.Config(s.c), // TODO only used to access Users and Groups, move that to dedicated options
				handler.YubiAuth(s.yubiAuth),
				handler.LDAPHelper(loh),
			)
		case "plugin":
			plug, err := plugin.Open(backend.Plugin)
			if err != nil {
				return nil, errors.New(fmt.Sprintf("Unable to load specified backend plugin: %s", err))
			}
			nph, err := plug.Lookup(backend.PluginHandler)
			if err != nil {
				return nil, errors.New("Unable to find 'NewPluginHandler' in loaded backend plugin")
			}
			initFunc, ok := nph.(func(...handler.Option) handler.Handler)

			if !ok {
				return nil, errors.New("Loaded backend plugin lacks a proper NewPluginHandler function")
			}
			// Normally, here, we would somehow have imported our plugin into our
			// handler namespace. Oops?
			h = initFunc(
				handler.Backend(backend),
				handler.Logger(s.log),
				handler.Config(s.c),
				handler.YubiAuth(s.yubiAuth),
				handler.LDAPHelper(loh),
			)
		default:
			return nil, fmt.Errorf("unsupported backend %s - must be one of 'config', 'ldap','owncloud' or 'plugin'", backend.Datastore)
		}
		s.log.Info("Loading backend", zap.String("datastore", backend.Datastore), zap.Int("position", i))

		// Only our first backend will answer proper LDAP queries.
		// Note that this could evolve towars something nicer where we would maintain
		// multiple binders in addition to the existing multiple LDAP backends
		if i == 0 {
			s.l.BindFunc("", h)
			s.l.SearchFunc("", h)
			s.l.CloseFunc("", h)
		}
		allHandlers.Handlers[i] = h
		backendCounter++
	}

	return &s, nil
}

// ListenAndServe listens on the TCP network address s.c.LDAP.Listen
func (s *LdapSvc) ListenAndServe() error {
	s.log.Info("LDAP server listening", zap.String("address", s.c.LDAP.Listen))
	return s.l.ListenAndServe(s.c.LDAP.Listen)
}

// ListenAndServeTLS listens on the TCP network address s.c.LDAPS.Listen
func (s *LdapSvc) ListenAndServeTLS() error {
	s.log.Info("LDAPS server listening", zap.String("address", s.c.LDAPS.Listen))
	return s.l.ListenAndServeTLS(
		s.c.LDAPS.Listen,
		s.c.LDAPS.Cert,
		s.c.LDAPS.Key,
	)
}

// Shutdown ends listeners by sending true to the ldap serves quit channel
func (s *LdapSvc) Shutdown() {
	s.l.Quit <- true
}
