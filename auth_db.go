package auth

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/yaitoo/auth/masker"
	"github.com/yaitoo/sqle"
	"github.com/yaitoo/sqle/shardid"
)

func (a *Auth) createBuilder() *sqle.Builder {
	return sqle.New().Input("prefix", a.prefix)
}

func (a *Auth) getUserByID(ctx context.Context, uid shardid.ID) (User, error) {
	var u User

	err := a.db.On(uid).
		QueryRowBuilder(ctx, a.createBuilder().
			Select("<prefix>user").
			Where("id = {id}").Param("id", uid.Int64)).
		Bind(&u)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return u, ErrUserNotFound
		}
		a.logger.Error("auth: getUserByID",
			slog.String("pos", "user"),
			slog.String("tag", "db"),
			slog.Int64("user_id", uid.Int64),
			slog.Any("err", err))
		return u, ErrBadDatabase
	}

	return u, nil
}

func (a *Auth) deleteUserToken(ctx context.Context, uid shardid.ID, token string) error {
	_, err := a.db.On(uid).
		ExecBuilder(ctx, a.createBuilder().
			Delete("<prefix>user_token").
			Where("user_id = {user_id}").
			If(token != "").And("hash = {hash}").
			Param("hash", hashToken(token)).
			Param("user_id", uid))

	if err != nil {
		a.logger.Error("auth: deleteUserToken",
			slog.String("tag", "db"),
			slog.Int64("user_id", uid.Int64),
			slog.Any("err", err))
		return ErrBadDatabase
	}
	return nil
}

// createUser creates a new user in the database with the provided information.
// It takes a context, a database connector, user ID, user status, password, first name, last name,
// email, mobile number, and the current time as input parameters.
// It returns the created User object and an error if any.
func (a *Auth) createUser(ctx context.Context, conn sqle.Connector, id shardid.ID, status UserStatus, passwd, firstName, lastName, email, mobile string, now time.Time) (User, error) {
	u := User{
		ID:        id,
		Status:    status,
		FirstName: firstName,
		LastName:  lastName,
		Salt:      randStr(10, dicAlphaNumber),
	}

	u.Passwd = generateHash(a.hash(), passwd, u.Salt)

	u.CreatedAt = now
	u.UpdatedAt = now

	_, err := conn.ExecBuilder(ctx, a.createBuilder().
		Insert("<prefix>user").
		Set("id", id).
		Set("status", status).
		Set("first_name", firstName).
		Set("last_name", lastName).
		Set("passwd", u.Passwd).
		Set("salt", u.Salt).
		Set("email", masker.Email(email)).
		Set("mobile", masker.Mobile(mobile)).
		Set("created_at", now).
		Set("updated_at", now).
		End())

	if err != nil {
		a.logger.Error("auth: createUser",
			slog.String("tag", "db"),
			slog.Int64("id", id.Int64),
			slog.Any("err", err))
		return u, ErrBadDatabase
	}
	return u, nil
}

// deleteUser deletes a user from the database based on the provided ID.
// It returns an error if the deletion fails.
func (a *Auth) deleteUser(ctx context.Context, conn sqle.Connector, id shardid.ID) error {
	_, err := conn.
		ExecBuilder(ctx, a.createBuilder().
			Delete("<prefix>user").
			Where("id = {id}").
			Param("id", id))

	if err != nil {
		a.logger.Error("auth: deleteUser",
			slog.String("tag", "db"),
			slog.Int64("id", id.Int64),
			slog.Any("err", err))
		return ErrBadDatabase
	}
	return nil
}

func (a *Auth) createLoginCode(ctx context.Context, userID shardid.ID, userIP string) (string, error) {
	code := randStr(a.loginCodeSize, dicNumber)

	now := time.Now()

	_, err := a.db.On(userID).
		ExecBuilder(ctx, a.createBuilder().
			Insert("<prefix>login_code").
			Set("user_id", userID.Int64).
			Set("hash", generateHash(a.hash(), code, "")).
			Set("user_ip", userIP).
			Set("expires_on", now.Add(a.loginCodeTTL)).
			Set("created_at", now).
			End())

	if err != nil {
		a.logger.Error("auth: createLoginCode",
			slog.Int64("user_id", userID.Int64),
			slog.Any("err", err))
		return "", ErrBadDatabase
	}
	return code, nil
}

func (a *Auth) getLoginCodeUserIP(ctx context.Context, userID shardid.ID, code string) (string, error) {
	h := generateHash(a.hash(), code, "")

	var userIP string
	err := a.db.On(userID).
		QueryRowBuilder(ctx, a.createBuilder().
			Select("<prefix>login_code", "user_ip").
			Where("user_id = {user_id} AND hash = {hash}").
			Param("user_id", userID.Int64).
			Param("hash", h)).
		Scan(&userIP)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrCodeNotMatched
		}
		a.logger.Error("auth: checkLoginCode",
			slog.Int64("user_id", userID.Int64),
			slog.String("code", code),
			slog.Any("err", err))
		return "", ErrBadDatabase
	}

	return userIP, nil
}

func (a *Auth) createSession(ctx context.Context, userID shardid.ID, firstName, lastName, userIP, userAgent string) (Session, error) {
	s := Session{
		UserID:    userID.Int64,
		FirstName: firstName,
		LastName:  lastName,
	}

	now := time.Now()
	accToken := jwt.NewWithClaims(jwt.SigningMethodHS256, UserClaims{
		ID:             userID.Int64,
		IssuedAt:       now.Unix(),
		ExpirationTime: now.Add(a.accessTokenTTL).Unix(),
	})

	exp := time.Now().Add(a.refreshTokenTTL)

	refToken := jwt.NewWithClaims(jwt.SigningMethodHS256, UserClaims{
		ID:             userID.Int64,
		Nonce:          randStr(12, dicAlphaNumber),
		IssuedAt:       now.Unix(),
		ExpirationTime: exp.Unix(),
	})

	var err error
	s.AccessToken, err = accToken.SignedString(a.jwtSignKey)
	if err != nil {
		a.logger.Error("auth: createSession",
			slog.String("tag", "token"),
			slog.String("step", "access_token"),
			slog.Any("err", err))
		return s, ErrUnknown
	}

	s.RefreshToken, err = refToken.SignedString(a.jwtSignKey)
	if err != nil {
		a.logger.Error("auth: createSession",
			slog.String("tag", "token"),
			slog.String("step", "refresh_token"),
			slog.Any("err", err))
		return s, ErrUnknown
	}

	_, err = a.db.On(userID).
		ExecBuilder(ctx, a.createBuilder().
			Insert("<prefix>user_token").
			Set("user_id", userID.Int64).
			Set("hash", hashToken(s.RefreshToken)).
			Set("user_ip", userID).
			Set("user_agent", userAgent).
			Set("expires_on", exp).
			Set("created_at", now).
			End())

	if err != nil {
		a.logger.Error("auth: createSession",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.Any("err", err))
		return s, ErrBadDatabase
	}

	return s, nil
}

func (a *Auth) checkRefreshToken(ctx context.Context, userID shardid.ID, token string) error {
	var count int
	err := a.db.On(userID).
		QueryRowBuilder(ctx, a.createBuilder().
			Select("<prefix>user_token", "count(user_id)").
			Where("user_id = {user_id} AND hash = {hash}").
			Param("user_id", userID.Int64).
			Param("hash", hashToken(token))).
		Scan(&count)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidToken
		}
		a.logger.Error("auth: checkRefreshToken",
			slog.Int64("user_id", userID.Int64),
			slog.String("token", token),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	if count == 0 {
		return ErrInvalidToken
	}

	return nil
}

func (a *Auth) getPermTag(ctx context.Context, code string) (string, error) {

	var v string

	err := a.db.
		QueryRowBuilder(ctx, a.createBuilder().
			Select("<prefix>perm", "tag").
			Where("code = {code}").End().
			Param("code", code)).
		Scan(&v)

	if err == nil {
		return v, nil
	}

	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrPermNotFound
	}

	a.logger.Error("auth: getPermTag",
		slog.String("tag", "db"),
		slog.String("code", code),
		slog.Any("err", err))
	return "", ErrBadDatabase
}

func (a *Auth) updatePerm(ctx context.Context, code, tag string) error {
	_, err := a.db.
		ExecBuilder(ctx, a.createBuilder().
			Update("<prefix>perm").
			Set("tag", tag).
			Set("updated_at", time.Now()).
			Where("code = {code}").
			Param("code", code))
	if err != nil {
		a.logger.Error("auth: updatePerm",
			slog.String("tag", "db"),
			slog.String("code", code),
			slog.String("perm_tag", tag),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	return nil
}

func (a *Auth) createPerm(ctx context.Context, code, tag string) error {
	now := time.Now()
	_, err := a.db.
		ExecBuilder(ctx, a.createBuilder().
			Insert("<prefix>perm").
			Set("code", code).
			Set("tag", tag).
			Set("created_at", now).
			Set("updated_at", now).
			End())

	if err != nil {
		a.logger.Error("auth: createPerm",
			slog.String("tag", "db"),
			slog.String("code", code),
			slog.String("perm_tag", tag),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	return nil
}
