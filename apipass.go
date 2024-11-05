package apipass

import (
	"fmt"
	"net/http"

	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("apipass", parseCaddyfile)
}

// Middleware
//
//	example.com {
//	    apipass {
//	        token "your-secret-token"
//	    }
//	    respond "Protected content"
//	}
type Middleware struct {
	Token string `json:"token,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apipass",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Before using the provider config, resolve placeholders in the API token.
// Implements caddy.Provisioner.
func (m *Middleware) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	m.Token = repl.ReplaceAll(m.Token, "")
	return nil
}

// Validate实现了caddy.Validator。
func (m *Middleware) Validate() error {
	if m.Token == "" {
		return fmt.Errorf("Token is empty")
	}
	return nil
}

// ServeHTTP 实现了 caddyhttp.MiddlewareHandler。
func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	auth := r.Header.Get("Authorization")
	expectedToken := fmt.Sprintf("Bearer %s", m.Token)

	if auth != expectedToken {
		w.Header().Set("WWW-Authenticate", `Bearer realm="Restricted"`)
		w.WriteHeader(http.StatusUnauthorized) // 返回 401
		return nil                             // 直接返回,不再调用 next handler
	}
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile sets up the Middleware from Caddyfile tokens. Syntax:
//
//	apipass {
//	    token "<your-api-token>"  # Required
//	}
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "token":
				if d.NextArg() {
					m.Token = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

// parseCaddyfile从h中解读令牌到一个新的中间件。
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
