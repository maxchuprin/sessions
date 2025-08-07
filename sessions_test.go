package sessions

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type initSessionStoreMock func(*mockSessionStore)

type mockSessionStore struct {
	mock.Mock
}

func (m *mockSessionStore) Create(session Session) error {
	args := m.Called(session)
	return args.Error(0)
}

func (m *mockSessionStore) Read(refreshToken string) (Session, error) {
	args := m.Called(refreshToken)
	return args.Get(0).(Session), args.Error(1)
}

func (m *mockSessionStore) Delete(refreshToken string) error {
	args := m.Called(refreshToken)
	return args.Error(0)
}

func TestStart(t *testing.T) {
	testCases := []struct {
		when    string
		current string
		err     error
		access  *http.Cookie
		refresh *http.Cookie
		initSS  initSessionStoreMock
	}{
		{
			when:    "Session.Start вернул неизвестную ошибку",
			current: "",
			err:     errors.New("Unknown error"),
			initSS: func(m *mockSessionStore) {
				m.On("Create", mock.Anything).Return(errors.New("Unknown error"))
			},
		},
		{
			when:    "Если все корректно",
			current: "session=123456",
			err:     nil,
			access:  &http.Cookie{MaxAge: 300},
			refresh: &http.Cookie{MaxAge: 600},
			initSS: func(m *mockSessionStore) {
				m.On("Delete", "123456").Return(nil)
				m.On("Create", mock.Anything).Return(nil)
			},
		},
	}

	e := echo.New()

	for _, tc := range testCases {
		t.Log(tc.when)

		req := httptest.NewRequest(http.MethodPost, "/auth", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderCookie, tc.current)
		rec := httptest.NewRecorder()

		mSessionStore := &mockSessionStore{}
		tc.initSS(mSessionStore)

		h := sessions{
			Secret:         []byte("secret"),
			AccessTimeout:  time.Minute * 5,
			RefreshTimeout: time.Minute * 10,
			Store:          mSessionStore,
		}

		c := e.NewContext(req, rec)

		claims := jwt.MapClaims{"Name": "Jhon Doe"}

		err := h.Start(c, claims)

		mSessionStore.AssertExpectations(t)

		assert.Equal(t, tc.err, err, "Некорректная ошибка обработчика")

		var ac *http.Cookie
		var rc *http.Cookie
		for _, ck := range rec.Result().Cookies() {
			if ck.Name == "access" {
				ac = ck
			}
			if ck.Name == "session" {
				rc = ck
			}
		}

		if tc.access != nil {
			if assert.NotNil(t, ac, "Отсутствует cookie с access-токеном") {
				assert.Equal(t, tc.access.MaxAge, ac.MaxAge)
			}
		}

		if tc.refresh != nil {
			if assert.NotNil(t, rc, "Отсутствует cookie с access-токеном") {
				assert.Equal(t, tc.refresh.MaxAge, rc.MaxAge)
			}
		}
	}
}

func TestStop(t *testing.T) {
	testCases := []struct {
		when    string
		current string
		err     error
		initSS  initSessionStoreMock
	}{
		{
			when:    "Нет cookie с сессией",
			current: "",
			err:     nil,
			initSS:  func(m *mockSessionStore) {},
		},
		{
			when:    "Если все корректно",
			current: "session=123456",
			err:     nil,
			initSS: func(m *mockSessionStore) {
				m.On("Delete", "123456").Return(nil)
			},
		},
	}

	e := echo.New()

	for _, tc := range testCases {
		t.Log(tc.when)

		req := httptest.NewRequest(http.MethodPost, "/auth", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderCookie, tc.current)
		rec := httptest.NewRecorder()

		mSessionStore := &mockSessionStore{}
		tc.initSS(mSessionStore)

		h := sessions{
			Secret: []byte("secret"),
			Store:  mSessionStore,
		}

		c := e.NewContext(req, rec)

		err := h.Stop(c)

		mSessionStore.AssertExpectations(t)

		assert.Equal(t, tc.err, err, "Некорректная ошибка обработчика")

		var ac *http.Cookie
		var rc *http.Cookie
		for _, ck := range rec.Result().Cookies() {
			if ck.Name == "access" {
				ac = ck
			}
			if ck.Name == "session" {
				rc = ck
			}
		}

		if assert.NotNil(t, ac, "Отсутствует cookie с access-токеном") {
			assert.Equal(t, -1, ac.MaxAge)
		}

		if assert.NotNil(t, rc, "Отсутствует cookie с access-токеном") {
			assert.Equal(t, -1, rc.MaxAge)
		}
	}
}

func TestRefresh(t *testing.T) {
	testCases := []struct {
		when     string
		current  string
		err      error
		access   *http.Cookie
		refresh  *http.Cookie
		redirect bool
		initSS   initSessionStoreMock
	}{
		{
			when:    "Нет cookie с сессией",
			current: "",
			err:     echo.ErrUnauthorized,
			initSS:  func(m *mockSessionStore) {},
		},
		{
			when:    "Если сессии нет в SessionStore",
			current: "session=123456",
			err:     echo.ErrUnauthorized,
			initSS: func(m *mockSessionStore) {
				m.On("Read", "123456").Return(Session{}, echo.ErrUnauthorized)
			},
		},
		{
			when:    "Если сессия истекла",
			current: "session=123456",
			err:     echo.ErrUnauthorized,
			access:  &http.Cookie{MaxAge: -1},
			refresh: &http.Cookie{MaxAge: -1},
			initSS: func(m *mockSessionStore) {
				s := Session{
					Token:   "123456",
					Claims:  jwt.MapClaims{"Name": "Jhon Doe"},
					Expired: time.Now().Add(-1 * time.Hour),
				}
				m.On("Read", "123456").Return(s, nil)
				m.On("Delete", "123456").Return(errors.New("Unknown error"))
			},
		},
		{
			when:    "Если текушая сессия не истекла, но SessionStore.Create вернул неизвестную ошибку",
			current: "session=123456",
			err:     errors.New("Unknown errror"),
			access:  &http.Cookie{MaxAge: -1},
			refresh: &http.Cookie{MaxAge: -1},
			initSS: func(m *mockSessionStore) {
				s := Session{
					Token:   "123456",
					Claims:  jwt.MapClaims{"Name": "Jhon Doe"},
					Expired: time.Now().Add(time.Hour),
				}
				m.On("Read", "123456").Return(s, nil)
				m.On("Delete", "123456").Return(nil)
				m.On("Create", mock.Anything).Return(errors.New("Unknown errror"))
			},
		},
		{
			when:     "Если все корректно",
			current:  "session=123456",
			err:      nil,
			access:   &http.Cookie{MaxAge: 300},
			refresh:  &http.Cookie{MaxAge: 600},
			redirect: true,
			initSS: func(m *mockSessionStore) {
				s := Session{
					Token:   "123456",
					Claims:  jwt.MapClaims{"Name": "Jhon Doe"},
					Expired: time.Now().Add(time.Hour),
				}
				m.On("Read", "123456").Return(s, nil)
				m.On("Delete", "123456").Return(nil)
				m.On("Create", mock.Anything).Return(nil)
			},
		},
	}

	e := echo.New()

	for _, tc := range testCases {
		t.Log(tc.when)

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderCookie, tc.current)
		rec := httptest.NewRecorder()

		mSessionStore := &mockSessionStore{}
		tc.initSS(mSessionStore)

		h := sessions{
			Secret:         []byte("secret"),
			AccessTimeout:  time.Minute * 5,
			RefreshTimeout: time.Minute * 10,
			Store:          mSessionStore,
		}

		c := e.NewContext(req, rec)
		c.SetPath("/auth/refresh/:uri")
		c.SetParamNames("uri")
		c.SetParamValues("api/v2")

		err := h.Refresh(c)

		mSessionStore.AssertExpectations(t)

		assert.Equal(t, tc.err, err, "Некорректная ошибка обработчика")

		var ac *http.Cookie
		var rc *http.Cookie
		for _, ck := range rec.Result().Cookies() {
			if ck.Name == "access" {
				ac = ck
			}
			if ck.Name == "session" {
				rc = ck
			}
		}

		if tc.access != nil {
			if assert.NotNil(t, ac, "Отсутствует cookie с access-токеном") {
				assert.Equal(t, tc.access.MaxAge, ac.MaxAge)
			}
		}

		if tc.refresh != nil {
			if assert.NotNil(t, rc, "Отсутствует cookie с access-токеном") {
				assert.Equal(t, tc.refresh.MaxAge, rc.MaxAge)
			}
		}

		if tc.redirect {
			assert.Equal(t, http.StatusTemporaryRedirect, rec.Code, "Некорректный http-статус ответа")
			assert.Equal(t, "/api/v2", rec.Header().Get(echo.HeaderLocation), "Некорректный путь редиректа")
		}
	}
}
