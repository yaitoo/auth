package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
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

func (a *Auth) getUserIDByEmail(ctx context.Context, email string) (shardid.ID, error) {
	var userID shardid.ID

	h := generateHash(a.hash(), email, "")

	db, err := a.db.OnDHT(h, a.dhtEmail)
	if err != nil {
		return userID, err
	}

	err = db.
		QueryRowBuilder(ctx, a.createBuilder().
			Select("<prefix>user_email", "user_id").
			Where("hash = {hash}").
			Param("hash", generateHash(a.hash(), email, ""))).
		Scan(&userID)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return userID, ErrEmailNotFound
		}
		a.logger.Error("auth: GetUserByEmail",
			slog.String("pos", "user_email"),
			slog.String("tag", "db"),
			slog.String("email", email),
			slog.Any("err", err))
		return userID, ErrBadDatabase
	}

	return userID, nil
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

func (a *Auth) createUser(ctx context.Context, tx *sqle.Tx, id shardid.ID, status UserStatus, passwd, firstName, lastName, email, mobile string, now time.Time) (User, error) {
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

	_, err := tx.ExecBuilder(ctx, a.createBuilder().
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

func (a *Auth) deleteUser(ctx context.Context, id shardid.ID) error {
	_, err := a.db.On(id).
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

func (a *Auth) deleteUserProfile(ctx context.Context, userID shardid.ID) error {

	_, err := a.db.On(userID).
		ExecBuilder(ctx, a.createBuilder().
			Delete("<prefix>user_profile").
			Where("user_id = {user_id}").
			Param("user_id", userID))

	if err != nil {
		a.logger.Error("auth: deleteUserProfile",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.Any("err", err))
		return ErrBadDatabase
	}
	return nil
}

func (a *Auth) createUserProfile(ctx context.Context, tx *sqle.Tx, userID shardid.ID, email, mobile string, now time.Time) (Profile, error) {

	p := Profile{
		UserID:    userID,
		CreatedAt: now,
		UpdatedAt: now,
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      a.totpIssuer,
		AccountName: a.totpAccountName,
	})

	if err != nil {
		a.logger.Error("auth: totp:Generate",
			slog.String("tag", "crypto"),
			slog.Any("err", err))
		return p, ErrUnknown
	}

	buf, _ := json.Marshal(ProfileData{
		Email:  email,
		Mobile: mobile,
		TKey:   key.Secret(),
	})

	if a.aesKey == nil {
		p.Data = string(buf)
	} else {
		ct, err := encryptText(buf, a.aesKey)
		if err != nil {
			a.logger.Error("auth: encryptText",
				slog.String("tag", "crypto"),
				slog.String("text", string(buf)),
				slog.Any("err", err))
			return p, ErrUnknown
		}

		p.Data = ct
	}

	_, err = tx.ExecBuilder(ctx, a.createBuilder().
		Insert("<prefix>user_profile").
		Set("user_id", userID).
		Set("data", p.Data).
		Set("created_at", now).
		Set("updated_at", now).
		End())

	if err != nil {
		a.logger.Error("auth: createUserProfile",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.Any("err", err))
		return p, ErrBadDatabase
	}
	return p, nil
}

func (a *Auth) createUserEmail(ctx context.Context, tx *sqle.Tx, userID shardid.ID, email, hash string, now time.Time) error {

	_, err := tx.ExecBuilder(ctx, a.createBuilder().
		Insert("<prefix>user_email").
		Set("user_id", userID).
		Set("hash", hash).
		Set("mask", masker.Email(email)).
		Set("is_verified", false).
		Set("created_at", now).
		End())

	if err != nil {
		a.logger.Error("auth: createUserEmail",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.String("email", email),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	return nil
}

func (a *Auth) deleteUserEmail(ctx context.Context, tx *sqle.Tx, userID shardid.ID, hash string) error {

	_, err := tx.ExecBuilder(ctx, a.createBuilder().
		Delete("<prefix>user_email").
		Where("hash = {hash} AND user_id = {user_id}").
		Param("hash", hash).
		Param("user_id", userID.Int64))

	if err != nil {
		a.logger.Error("auth: deleteUserEmail",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.String("hash", hash),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	return nil
}

func (a *Auth) getUserIDByMobile(ctx context.Context, mobile string) (shardid.ID, error) {
	var userID shardid.ID

	h := generateHash(a.hash(), mobile, "")

	db, err := a.db.OnDHT(h, a.dhtMobile)
	if err != nil {
		return userID, err
	}

	err = db.
		QueryRowBuilder(ctx, a.createBuilder().
			Select("<prefix>user_mobile", "user_id").
			Where("hash = {hash}").
			Param("hash", generateHash(a.hash(), mobile, ""))).
		Scan(&userID)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return userID, ErrMobileNotFound
		}
		a.logger.Error("auth: GetUserByMobile",
			slog.String("pos", "user_mobile"),
			slog.String("tag", "db"),
			slog.String("mobile", mobile),
			slog.Any("err", err))
		return userID, ErrBadDatabase
	}

	return userID, nil
}

func (a *Auth) createUserMobile(ctx context.Context, tx *sqle.Tx, userID shardid.ID, mobile, hash string, now time.Time) error {

	_, err := tx.ExecBuilder(ctx, a.createBuilder().
		Insert("<prefix>user_mobile").
		Set("user_id", userID).
		Set("hash", hash).
		Set("mask", masker.Mobile(mobile)).
		Set("is_verified", false).
		Set("created_at", now).
		End())

	if err != nil {
		a.logger.Error("auth: createUserMobile",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.String("mobile", mobile),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	return nil
}

func (a *Auth) deleteUserMobile(ctx context.Context, tx *sqle.Tx, userID shardid.ID, hash string) error {

	_, err := tx.ExecBuilder(ctx, a.createBuilder().
		Delete("<prefix>user_mobile").
		Where("hash = {hash} AND user_id = {user_id}").
		Param("hash", hash).
		Param("user_id", userID.Int64))

	if err != nil {
		a.logger.Error("auth: createUserMobile",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.String("hash", hash),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	return nil
}

func (a *Auth) getUserProfileData(ctx context.Context, userID shardid.ID) (ProfileData, error) {
	var data string
	err := a.db.On(userID).
		QueryRowBuilder(ctx, a.createBuilder().
			Select("<prefix>user_profile", "data").
			Where("user_id = {user_id}").
			Param("user_id", userID)).
		Scan(&data)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return noProfileData, ErrProfileNotFound
		}
		a.logger.Error("auth: getUserProfileData",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.Any("err", err))
		return noProfileData, ErrBadDatabase
	}

	if data == "" {
		return noProfileData, ErrProfileNotFound
	}

	var pd ProfileData

	if a.aesKey != nil {
		data, err = decryptText(data, a.aesKey)
		if err != nil {
			a.logger.Error("auth: getUserProfileData",
				slog.String("step", "decryptText"),
				slog.String("tag", "crypto"),
				slog.String("text", data),
				slog.Any("err", err))

			return noProfileData, ErrUnknown
		}
	}

	err = json.Unmarshal([]byte(data), &pd)
	if err != nil {
		a.logger.Error("auth: getUserProfileData",
			slog.String("step", "json"),
			slog.Int64("user_id", userID.Int64),
			slog.Any("err", err))
		return noProfileData, ErrUnknown
	}

	return pd, nil
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
		a.logger.Error("auth: createloginCode",
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
		a.logger.Error("auth: checkloginCode",
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
