package sessions

import (
	"net/http"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func JWTWithRedirect(path string, secret []byte, claims jwt.Claims) echo.MiddlewareFunc {
	return middleware.JWTWithConfig(middleware.JWTConfig{
		TokenLookup: "cookie:access",
		SigningKey:  secret,
		Claims:      claims,
		ErrorHandlerWithContext: func(err error, c echo.Context) error {
			if err == middleware.ErrJWTMissing {
				return c.Redirect(http.StatusTemporaryRedirect, path+c.Request().RequestURI)
			}
			return err
		},
	})
}
