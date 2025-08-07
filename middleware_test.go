package sessions

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/stretchr/testify/assert"
)

type mockClaims struct {
	Name string
	jwt.StandardClaims
}

func TestJWTWithRedirect(t *testing.T) {
	testCases := []struct {
		when     string
		current  string
		err      error
		redirect bool
		claims   *mockClaims
	}{
		{
			when:     "Нет cookie с access-токеном",
			redirect: true,
		},
		{
			when:    "Все в порядке",
			current: "access=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJOYW1lIjoiSmhvbiBEb2UifQ.hsShW3pRWuxeYtxaXf-igfnhexKQzoJqEl5zFjKyWl4",
			err:     nil,
			claims:  &mockClaims{Name: "Jhon Doe"},
		},
	}

	e := echo.New()

	h := JWTWithRedirect("/auth/refresh", []byte("secret"), &mockClaims{})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})

	for _, tc := range testCases {
		t.Log(tc.when)

		req := httptest.NewRequest(http.MethodPost, "/api/v2", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderCookie, tc.current)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		assert.Equal(t, tc.err, h(c), "Некорректный код ошибки обработчика")

		if tc.redirect {
			assert.Equal(t, http.StatusTemporaryRedirect, rec.Code, "Некорректный http-статус ответа")
			assert.Equal(t, "/auth/refresh/api/v2", rec.Header().Get(echo.HeaderLocation), "Некорректный путь редиректа")
		} else {
			if tc.claims != nil {
				token := c.Get("user").(*jwt.Token)
				u := token.Claims.(*mockClaims)
				assert.Equal(t, tc.claims, u, "Некорректная информация о пользователе")

			}
		}
	}
}

func TestToken(t *testing.T) {
	claims := jwt.MapClaims{"Name": "Jhon Doe"}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("secret"))
	assert.NoError(t, err, "err")
	assert.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJOYW1lIjoiSmhvbiBEb2UifQ.hsShW3pRWuxeYtxaXf-igfnhexKQzoJqEl5zFjKyWl4", token, "token")

	config := middleware.JWTConfig{
		Claims:      &mockClaims{},
		SigningKey:  []byte("secret"),
		TokenLookup: "cookie:access",
	}

	h := middleware.JWTWithConfig(config)(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v2", nil)
	req.Header.Set(echo.HeaderCookie, "access=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJOYW1lIjoiSmhvbiBEb2UifQ.hsShW3pRWuxeYtxaXf-igfnhexKQzoJqEl5zFjKyWl4")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = h(c)
	assert.NoError(t, err, "handler")

	tk := c.Get("user").(*jwt.Token)
	cl := tk.Claims.(*mockClaims)
	assert.Equal(t, "Jhon Doe", cl.Name, "claims")
}
