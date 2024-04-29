package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/yaitoo/auth/masker"
	"github.com/yaitoo/sqle"
	"github.com/yaitoo/sqle/shardid"
)

// UpdateProfile updates the profile of a user identified by the given ID.
// It updates the email and mobile fields of the user's profile.
// If the email or mobile value is empty, it will delete the corresponding field.
// If the email or mobile value is different from the current value in the profile, it will update the field.
// The function uses a transaction to ensure atomicity of the database operations.
// It returns an error if any of the database operations fail.
func (a *Auth) UpdateProfile(ctx context.Context, id int64, email, mobile string) error {

	uid := shardid.Parse(id)
	dbUser := a.db.On(uid)

	pd, err := a.GetProfileData(ctx, dbUser, id)
	if err != nil {
		return err
	}

	if pd.Email == email && pd.Mobile == mobile {
		return nil
	}

	oldEmail := pd.Email
	oldMobile := pd.Mobile
	now := time.Now()
	dtc := sqle.NewDTC(ctx, nil)

	// create/delete/update email
	if pd.Email != email {
		if email == "" { // delete email
			hashEmail := generateHash(a.hash(), pd.Email, "")
			dbEmail, err := a.db.OnDHT(hashEmail, a.dhtEmail)
			if err != nil {
				return err
			}

			dtc.Prepare(dbEmail, func(ctx context.Context, conn sqle.Connector) error {
				return a.deleteEmail(ctx, conn, uid, hashEmail)
			}, func(ctx context.Context, conn sqle.Connector) error {
				return a.createEmail(ctx, conn, uid, oldEmail, hashEmail, now)
			})

		} else if pd.Email == "" { // create email {
			hashEmail := generateHash(a.hash(), email, "")
			dbEmail, err := a.db.OnDHT(hashEmail, a.dhtEmail)
			if err != nil {
				return err
			}

			dtc.Prepare(dbEmail, func(ctx context.Context, conn sqle.Connector) error {
				return a.createEmail(ctx, conn, uid, email, hashEmail, now)
			}, func(ctx context.Context, conn sqle.Connector) error {
				return a.deleteEmail(ctx, conn, uid, hashEmail)
			})
		} else { // update email
			hashOldEmail := generateHash(a.hash(), pd.Email, "")
			dbOldEmail, err := a.db.OnDHT(hashOldEmail, a.dhtEmail)
			if err != nil {
				return err
			}

			hashNewEmail := generateHash(a.hash(), email, "")
			dbNewEmail, err := a.db.OnDHT(hashNewEmail, a.dhtEmail)
			if err != nil {
				return err
			}

			dtc.Prepare(dbNewEmail, func(ctx context.Context, conn sqle.Connector) error {
				return a.createEmail(ctx, conn, uid, email, hashNewEmail, now)
			}, func(ctx context.Context, conn sqle.Connector) error {
				return a.deleteEmail(ctx, conn, uid, hashNewEmail)
			})

			dtc.Prepare(dbOldEmail, func(ctx context.Context, conn sqle.Connector) error {
				return a.deleteEmail(ctx, conn, uid, hashOldEmail)
			}, func(ctx context.Context, conn sqle.Connector) error {
				return a.createEmail(ctx, conn, uid, oldEmail, hashOldEmail, now)
			})

		}
	}

	// create/delete/update mobile
	if pd.Mobile != mobile {
		if mobile == "" { // delete mobile
			hashMobile := generateHash(a.hash(), pd.Mobile, "")
			dbMobile, err := a.db.OnDHT(hashMobile, a.dhtMobile)
			if err != nil {
				return err
			}

			dtc.Prepare(dbMobile, func(ctx context.Context, conn sqle.Connector) error {
				return a.deleteMobile(ctx, conn, uid, hashMobile)
			}, func(ctx context.Context, conn sqle.Connector) error {
				return a.createMobile(ctx, conn, uid, oldMobile, hashMobile, now)
			})

		} else if pd.Mobile == "" { // create mobile
			hashMobile := generateHash(a.hash(), mobile, "")
			dbMobile, err := a.db.OnDHT(hashMobile, a.dhtMobile)
			if err != nil {
				return err
			}

			dtc.Prepare(dbMobile, func(ctx context.Context, conn sqle.Connector) error {
				return a.createMobile(ctx, conn, uid, mobile, hashMobile, now)
			}, func(ctx context.Context, conn sqle.Connector) error {
				return a.deleteMobile(ctx, conn, uid, hashMobile)
			})
		} else { // update mobile
			hashOldMobile := generateHash(a.hash(), pd.Mobile, "")
			dbOldMobile, err := a.db.OnDHT(hashOldMobile, a.dhtMobile)
			if err != nil {
				return err
			}

			hashNewMobile := generateHash(a.hash(), mobile, "")
			dbNewMobile, err := a.db.OnDHT(hashNewMobile, a.dhtMobile)
			if err != nil {
				return err
			}

			dtc.Prepare(dbNewMobile, func(ctx context.Context, conn sqle.Connector) error {
				return a.createMobile(ctx, conn, uid, mobile, hashNewMobile, now)
			}, func(ctx context.Context, conn sqle.Connector) error {
				return a.deleteMobile(ctx, conn, uid, hashNewMobile)
			})

			dtc.Prepare(dbOldMobile, func(ctx context.Context, conn sqle.Connector) error {
				return a.deleteMobile(ctx, conn, uid, hashOldMobile)
			}, func(ctx context.Context, conn sqle.Connector) error {
				return a.createMobile(ctx, conn, uid, oldMobile, hashOldMobile, now)
			})
		}
	}

	pd.Email = email
	pd.Mobile = mobile
	dtc.Prepare(dbUser, func(ctx context.Context, conn sqle.Connector) error {
		return a.updateProfileData(ctx, conn, id, pd, now)
	}, nil)

	return nil
}

// createProfile creates a new profile for the given user with the provided email, mobile, and current timestamp.
// It generates a TOTP key and encrypts the profile data using the AES key if available.
// The profile is then inserted into the "user_profile" table using the provided database connection.
// Returns the created profile and any error encountered during the process.
func (a *Auth) createProfile(ctx context.Context, conn sqle.Connector, userID shardid.ID, email, mobile string, now time.Time) (Profile, error) {

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

	_, err = conn.ExecBuilder(ctx, a.createBuilder().
		Insert("<prefix>user_profile").
		Set("user_id", userID).
		Set("data", p.Data).
		Set("created_at", now).
		Set("updated_at", now).
		End())

	if err != nil {
		a.logger.Error("auth: createProfile",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.Any("err", err))
		return p, ErrBadDatabase
	}
	return p, nil
}

// deleteProfile deletes the user profile associated with the given userID.
// It takes a context, a database connector, and the userID as parameters.
// It returns an error if the deletion fails.
func (a *Auth) deleteProfile(ctx context.Context, conn sqle.Connector, userID shardid.ID) error {

	_, err := conn.
		ExecBuilder(ctx, a.createBuilder().
			Delete("<prefix>user_profile").
			Where("user_id = {user_id}").
			Param("user_id", userID))

	if err != nil {
		a.logger.Error("auth: deleteProfile",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.Any("err", err))
		return ErrBadDatabase
	}
	return nil
}

// GetProfileData retrieves the profile data for a given user ID.
// It takes a context, a database connector, and the user ID as parameters.
// It returns the profile data as a ProfileData struct and an error if any.
// If the profile data is not found, it returns a default profile data and ErrProfileNotFound error.
// If there is an error accessing the database, it returns a default profile data and ErrBadDatabase error.
// If there is an error decrypting the profile data, it returns a default profile data and ErrUnknown error.
// If there is an error unmarshaling the profile data, it returns a default profile data and ErrUnknown error.
func (a *Auth) GetProfileData(ctx context.Context, conn sqle.Connector, id int64) (ProfileData, error) {
	var data string
	err := conn.
		QueryRowBuilder(ctx, a.createBuilder().
			Select("<prefix>user_profile", "data").
			Where("user_id = {user_id}").
			Param("user_id", id)).
		Scan(&data)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return noProfileData, ErrProfileNotFound
		}
		a.logger.Error("auth: getProfileData",
			slog.String("tag", "db"),
			slog.Int64("user_id", id),
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
			a.logger.Error("auth: getProfileData",
				slog.String("step", "decryptText"),
				slog.String("tag", "crypto"),
				slog.String("text", data),
				slog.Any("err", err))

			return noProfileData, ErrUnknown
		}
	}

	err = json.Unmarshal([]byte(data), &pd)
	if err != nil {
		a.logger.Error("auth: getProfileData",
			slog.String("step", "json"),
			slog.Int64("user_id", id),
			slog.Any("err", err))
		return noProfileData, ErrUnknown
	}

	return pd, nil
}

// updateProfileData updates the profile data for a user in the database.
// It takes the following parameters:
// - ctx: The context.Context object for the request.
// - conn: The sqle.Connector object for executing SQL queries.
// - id: The ID of the user whose profile data needs to be updated.
// - pd: The ProfileData struct containing the updated profile data.
// - now: The current time.
// It returns an error if there was a problem updating the profile data.
func (a *Auth) updateProfileData(ctx context.Context, conn sqle.Connector, id int64, pd ProfileData, now time.Time) error {

	_, err := conn.ExecBuilder(ctx, a.createBuilder().
		Update("<prefix>user").
		Set("email", masker.Email(pd.Email)).
		Set("mobile", masker.Mobile(pd.Mobile)).
		Set("updated_at", now).
		Where("id = {id}").
		Param("id", id))
	if err != nil {
		a.logger.Error("auth: updateProfileData:User",
			slog.String("tag", "db"),
			slog.Int64("id", id),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	buf, _ := json.Marshal(pd)

	var data string

	if a.aesKey == nil {
		data = string(buf)
	} else {
		ct, err := encryptText(buf, a.aesKey)
		if err != nil {
			a.logger.Error("auth: encryptText",
				slog.String("tag", "crypto"),
				slog.String("text", string(buf)),
				slog.Any("err", err))
			return ErrUnknown
		}

		data = ct
	}

	_, err = conn.ExecBuilder(ctx, a.createBuilder().
		Update("<prefix>user_profile").
		Set("data", data).
		Set("updated_at", now).
		Where("user_id = {user_id}").Param("user_id", id))

	if err != nil {
		a.logger.Error("auth: updateProfileData:Profile",
			slog.String("tag", "db"),
			slog.Int64("user_id", id),
			slog.Any("err", err))
		return ErrBadDatabase
	}
	return nil
}
