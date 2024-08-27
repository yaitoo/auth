package auth

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/yaitoo/sqle/shardid"
)

type ctxKey string

var (
	currentUser ctxKey = "cu"
)

type CurrentUser struct {
	UserID shardid.ID

	// IP user's ip address
	UserIP string
	// UserAgent user's device info
	UserAgent string
}

type Handler struct {
	db          *Auth
	permissions []Perm

	getUserIP      func(*http.Request) string
	getAccessToken func(*http.Request) string

	cachedUserPerms     *expirable.LRU[int64, map[string]bool]
	cachedUserPermsTTL  time.Duration
	cachedUserPermsSize int
}

type HandlerOption func(h *Handler)

type LoginForm struct {
	Email  string `json:"email,omitempty"`
	Passwd string `json:"passwd,omitempty"`
}

func NewHandler(db *Auth, options ...HandlerOption) *Handler {
	h := &Handler{
		db: db,

		cachedUserPermsTTL:  1 * time.Minute,
		cachedUserPermsSize: 1024,

		getUserIP: func(r *http.Request) string {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				return r.RemoteAddr
			}

			return host

		},
		getAccessToken: func(r *http.Request) string {
			return r.Header.Get("X-Access-Token")
		},
	}

	for _, opt := range options {
		opt(h)
	}

	h.cachedUserPerms = expirable.NewLRU[int64, map[string]bool](h.cachedUserPermsSize, nil, h.cachedUserPermsTTL)

	return h
}

func WithGetUserIP(fn func(*http.Request) string) HandlerOption {
	return func(h *Handler) {
		h.getUserIP = fn
	}
}

func WithGetAccessToken(fn func(*http.Request) string) HandlerOption {
	return func(h *Handler) {
		h.getAccessToken = fn
	}
}

func WithUserPermsCache(ttl time.Duration, size int) HandlerOption {
	return func(h *Handler) {
		h.cachedUserPermsTTL = ttl
		h.cachedUserPermsSize = size
	}
}

// WithAuthn returns a middleware that checks the user is authenticated.
func (h *Handler) WithAuthn(ctx context.Context, handler func(context.Context, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {
		s, err := h.getCurrentUser(ctx, r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		handler(context.WithValue(ctx, currentUser, s), w, r)
	}
}

// WithAuthz returns a middleware that checks the user's permissions.
func (h *Handler) WithAuthz(ctx context.Context, tag, code string, handler func(context.Context, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	h.permissions = append(h.permissions, Perm{Tag: tag, Code: code})

	return func(w http.ResponseWriter, r *http.Request) {
		s := &CurrentUser{}
		s.UserAgent = r.UserAgent()
		s.UserIP = h.getUserIP(r)
		accessToken := h.getAccessToken(r)

		id, err := h.db.IsAuthenticated(ctx, accessToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		s.UserID = id

		perms := h.getUserPerms(ctx, id.Int64)
		ok := perms[code]

		if !ok {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		handler(context.WithValue(ctx, currentUser, s), w, r)
	}
}

func (h *Handler) Login(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	form, err := BindJSON[LoginForm](r)
	if err != nil {
		WriteClientError(w, err)
		return
	}

	session, err := h.db.Login(ctx, form.Email, form.Passwd, LoginOption{
		UserIP:            h.getUserIP(r),
		UserAgent:         r.UserAgent(),
		CreateIfNotExists: false,
	})
	if err != nil {
		WriteClientError(w, err)
		return
	}

	perms, err := h.db.GetUserPerms(ctx, session.UserID)
	if err == nil {
		go h.cacheUserPerms(session.UserID, perms)
	} else {
		h.db.logger.Error("auth: login", slog.String("tag", "db"), slog.Any("err", err))
	}

	WriteJSON(w, struct {
		Session
		Perms []string `json:"perms,omitempty"`
	}{
		Session: session,
		Perms:   perms,
	})
}

func (h *Handler) Logout(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user, ok := GetCurrentUser(ctx)
	if !ok {
		WriteClientError(w, ErrBadRequest)
		return
	}

	err := h.db.Logout(ctx, user.UserID)
	if err != nil {
		WriteServerError(w, err)
		return
	}

	WriteEmpty(w)
}

func (h *Handler) RegisterPerms() {
	for _, it := range h.permissions {
		h.db.RegisterPerm(context.TODO(), it.Code, it.Tag)
	}
}

func (h *Handler) getUserPerms(ctx context.Context, uid int64) map[string]bool {
	perms, ok := h.cachedUserPerms.Get(uid)
	if ok {
		return perms
	}

	perms = map[string]bool{}
	items, err := h.db.GetUserPerms(ctx, uid)
	if err != nil {
		h.db.logger.Error("auth: getUserPerms ", slog.Int64("uid", uid), slog.Any("err", err))
	} else {
		for _, it := range items {
			perms[it] = true
		}
		h.cachedUserPerms.Add(uid, perms)
	}

	return perms
}

func (h *Handler) cacheUserPerms(uid int64, items []string) {
	perms := make(map[string]bool)
	for _, it := range items {
		perms[it] = true
	}

	h.cachedUserPerms.Add(uid, perms)
}

func (h *Handler) getCurrentUser(ctx context.Context, r *http.Request) (CurrentUser, error) {
	s := CurrentUser{}
	s.UserAgent = r.UserAgent()
	s.UserIP = h.getUserIP(r)
	accessToken := h.getAccessToken(r)

	id, err := h.db.IsAuthenticated(ctx, accessToken)
	if err != nil {
		return s, err
	}
	s.UserID = id

	return s, nil
}

func GetCurrentUser(ctx context.Context) (CurrentUser, bool) {
	cu, ok := ctx.Value(currentUser).(CurrentUser)
	return cu, ok
}

func BindJSON[T any](req *http.Request, options ...Option) (T, error) {

	var i T

	buf, err := io.ReadAll(req.Body)
	if err != nil {
		return i, ErrBadRequest
	}
	defer req.Body.Close()

	err = json.Unmarshal(buf, &i)
	if err != nil {
		return i, ErrBadRequest
	}

	return i, nil
}

func Write[T any](w http.ResponseWriter, statusCode int, result T, err error) {
	w.WriteHeader(statusCode)
	w.Header().Set("Content-Type", "application/json")

	jr := JsonResult[T]{
		Code:   statusCode,
		Result: result,
	}
	if err != nil {
		jr.ErrorCode = err.Error()
		// TODO: added i18n for error
		jr.ErrorMessage = err.Error()
	}

	//nolint: errcheck
	json.NewEncoder(w).Encode(jr)
}

func WriteEmpty(w http.ResponseWriter) {
	Write[any](w, http.StatusOK, nil, nil)
}

func WriteJSON[T any](w http.ResponseWriter, result T) {
	Write(w, http.StatusOK, result, nil)
}

func WriteError(w http.ResponseWriter, statusCode int, err error) {
	Write[any](w, statusCode, nil, err)
}

func WriteServerError(w http.ResponseWriter, err error) {
	Write[any](w, http.StatusInternalServerError, nil, err)
}

func WriteClientError(w http.ResponseWriter, err error) {
	Write[any](w, http.StatusBadRequest, nil, err)
}

type JsonResult[T any] struct {
	Code         int    `json:"code,omitempty"`
	Result       T      `json:"result,omitempty"`
	ErrorCode    string `json:"errorCode,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

type JsonMessage struct {
	Code         int    `json:"code,omitempty"`
	ErrorCode    string `json:"errorCode,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}
