package sessions

import (
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type Sessions interface {
	Start(c echo.Context, claims jwt.MapClaims) error
	Stop(c echo.Context) error
	Refresh(c echo.Context) error
}

type SessionStore interface {
	Create(Session) error
	Read(refreshToken string) (Session, error)
	Delete(refreshToken string) error
}

type Device struct {
	IP        string
	UserAgent string
}

type Session struct {
	Token   string
	Claims  jwt.MapClaims
	Device  Device
	Created time.Time
	Expired time.Time
}

func New(secret []byte, accessTimeout time.Duration, refreshTimeout time.Duration, store SessionStore) Sessions {
	return &sessions{
		Secret:         secret,
		AccessTimeout:  accessTimeout,
		RefreshTimeout: refreshTimeout,
		Store:          store,
	}
}

type sessions struct {
	Secret         []byte
	AccessTimeout  time.Duration
	RefreshTimeout time.Duration
	Store          SessionStore
}

func (s *sessions) Start(c echo.Context, claims jwt.MapClaims) error {
	current, err := c.Cookie("session")
	if err == nil && current != nil {
		if err := s.Store.Delete(current.Value); err != nil {
			c.Logger().Info("Sessions.Start: Ошибка удаления сессии из SessionStore")
		}
	}

	return s.start(c, claims)
}

func (s *sessions) Stop(c echo.Context) error {
	current, err := c.Cookie("session")
	if err != http.ErrNoCookie {
		if err := s.Store.Delete(current.Value); err != nil {
			c.Logger().Info("Sessions.Stop: Ошибка удаления сессии из SessionStore")
		}
	}

	s.clearCookies(c)
	return nil
}

var refreshLocks sync.Map

func (s *sessions) Refresh(c echo.Context) error {
	cookie, err := c.Cookie("session")
	if err != nil || cookie == nil {
		return echo.ErrUnauthorized
	}

	token := cookie.Value

	mutexIface, _ := refreshLocks.LoadOrStore(token, &sync.Mutex{})
	mutex := mutexIface.(*sync.Mutex)

	mutex.Lock()
	defer mutex.Unlock()

	current, err := s.Store.Read(token)
	if err != nil {
		s.clearCookies(c)
		return echo.ErrUnauthorized
	}

	if time.Now().Before(current.Expired) {
		claims := current.Claims
		claims["exp"] = time.Now().Add(s.AccessTimeout).Unix()

		access, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.Secret)
		if err != nil {
			s.clearCookies(c)
			return echo.ErrUnauthorized
		}

		s.setCookies(c, access, current.Token)

		uri := "/" + c.Param("uri")
		return c.Redirect(http.StatusTemporaryRedirect, uri)
	}

	if err := s.Store.Delete(current.Token); err != nil {
		c.Logger().Info("Sessions.Refresh: Ошибка удаления сессии из SessionStore")
	}

	s.clearCookies(c)

	err = s.start(c, current.Claims)
	if err != nil {
		return echo.ErrUnauthorized
	}

	uri := "/" + c.Param("uri")
	return c.Redirect(http.StatusTemporaryRedirect, uri)
}

func (s *sessions) start(c echo.Context, claims jwt.MapClaims) error {
	claims["exp"] = time.Now().Add(s.AccessTimeout).Unix()

	access, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.Secret)
	if err != nil {
		return err
	}

	session := Session{
		Token:  uuid.NewString(),
		Claims: claims,
		Device: Device{
			IP:        c.Request().RemoteAddr,
			UserAgent: c.Request().UserAgent(),
		},
		Created: time.Now(),
		Expired: time.Now().Add(s.RefreshTimeout),
	}

	if err := s.Store.Create(session); err != nil {
		s.clearCookies(c)
		return err
	}

	s.setCookies(c, access, session.Token)
	return nil
}

func (s *sessions) setCookies(c echo.Context, accessToken string, refreshToken string) {
	c.SetCookie(&http.Cookie{
		Name:     "session",
		Value:    refreshToken,
		MaxAge:   int(s.RefreshTimeout.Seconds()),
		Expires:  time.Now().Add(s.RefreshTimeout),
		Domain:   c.Request().Host,
		Path:     "/auth",
		HttpOnly: true,
		Secure:   c.Request().Host != "localhost",
		SameSite: http.SameSiteLaxMode,
	})

	c.SetCookie(&http.Cookie{
		Name:     "access",
		Value:    accessToken,
		MaxAge:   int(s.AccessTimeout.Seconds()),
		Expires:  time.Now().Add(s.AccessTimeout),
		Domain:   c.Request().Host,
		Path:     "/",
		HttpOnly: false,
		Secure:   c.Request().Host != "localhost",
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *sessions) clearCookies(c echo.Context) {
	c.SetCookie(&http.Cookie{
		Name:     "session",
		Value:    "",
		MaxAge:   -1,
		Expires:  time.Now(),
		Domain:   c.Request().Host,
		Path:     "/auth",
		HttpOnly: true,
		Secure:   c.Request().Host != "localhost",
		SameSite: http.SameSiteLaxMode,
	})

	c.SetCookie(&http.Cookie{
		Name:     "access",
		Value:    "",
		MaxAge:   -1,
		Expires:  time.Now(),
		Domain:   c.Request().Host,
		Path:     "/",
		HttpOnly: false,
		Secure:   c.Request().Host != "localhost",
		SameSite: http.SameSiteLaxMode,
	})
}
