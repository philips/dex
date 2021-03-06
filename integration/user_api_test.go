package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/key"
	"github.com/coreos/go-oidc/oidc"
	"github.com/kylelemons/godebug/pretty"
	"google.golang.org/api/googleapi"

	"github.com/coreos/dex/client"
	schema "github.com/coreos/dex/schema/workerschema"
	"github.com/coreos/dex/server"
	"github.com/coreos/dex/user"
	"github.com/coreos/dex/user/api"
)

type userAPITestFixtures struct {
	client  *schema.Service
	hSrv    *httptest.Server
	emailer *testEmailer
	trans   *tokenHandlerTransport
}

func (f *userAPITestFixtures) close() {
	f.hSrv.Close()
}

var (
	userUsers = []user.UserWithRemoteIdentities{
		{
			User: user.User{
				ID:    "ID-1",
				Email: "Email-1@example.com",
				Admin: true,
			},
		},
		{
			User: user.User{
				ID:    "ID-2",
				Email: "Email-2@example.com",
			},
		},
		{
			User: user.User{
				ID:    "ID-3",
				Email: "Email-3@example.com",
			},
		},
		{
			User: user.User{
				ID:       "ID-4",
				Email:    "Email-4@example.com",
				Admin:    true,
				Disabled: true,
			},
		},
	}

	userPasswords = []user.PasswordInfo{
		{
			UserID:   "ID-1",
			Password: []byte("hi."),
		},
		{
			UserID:   "ID-4",
			Password: []byte("hi."),
		},
	}

	userBadClientID = "ZZZ"

	userGoodToken = makeUserToken(testIssuerURL,
		"ID-1", testClientID, time.Hour*1, testPrivKey)

	userBadTokenNotAdmin = makeUserToken(testIssuerURL,
		"ID-2", testClientID, time.Hour*1, testPrivKey)

	userBadTokenClientNotAdmin = makeUserToken(testIssuerURL,
		"ID-1", userBadClientID, time.Hour*1, testPrivKey)

	userBadTokenExpired = makeUserToken(testIssuerURL,
		"ID-1", testClientID, time.Hour*-1, testPrivKey)

	userBadTokenDisabled = makeUserToken(testIssuerURL,
		"ID-4", testClientID, time.Hour*1, testPrivKey)
)

func makeUserAPITestFixtures() *userAPITestFixtures {
	f := &userAPITestFixtures{}

	_, _, um := makeUserObjects(userUsers, userPasswords)

	cir := client.NewClientIdentityRepo([]oidc.ClientIdentity{
		oidc.ClientIdentity{
			Credentials: oidc.ClientCredentials{
				ID:     testClientID,
				Secret: testClientSecret,
			},
			Metadata: oidc.ClientMetadata{
				RedirectURLs: []url.URL{
					testRedirectURL,
				},
			},
		},
		oidc.ClientIdentity{
			Credentials: oidc.ClientCredentials{
				ID:     userBadClientID,
				Secret: "secret",
			},
			Metadata: oidc.ClientMetadata{
				RedirectURLs: []url.URL{
					testRedirectURL,
				},
			},
		},
	})

	cir.SetDexAdmin(testClientID, true)

	noop := func() error { return nil }

	keysFunc := func() []key.PublicKey {
		return []key.PublicKey{*key.NewPublicKey(testPrivKey.JWK())}
	}

	jwtvFactory := func(clientID string) oidc.JWTVerifier {
		return oidc.NewJWTVerifier(testIssuerURL.String(), clientID, noop, keysFunc)
	}

	f.emailer = &testEmailer{}
	api := api.NewUsersAPI(um, cir, f.emailer, "local")
	usrSrv := server.NewUserMgmtServer(api, jwtvFactory, um, cir)
	f.hSrv = httptest.NewServer(usrSrv.HTTPHandler())

	f.trans = &tokenHandlerTransport{
		Handler: usrSrv.HTTPHandler(),
		Token:   userGoodToken,
	}
	hc := &http.Client{
		Transport: f.trans,
	}
	f.client, _ = schema.NewWithBasePath(hc, f.hSrv.URL)

	return f
}

func TestGetUser(t *testing.T) {
	tests := []struct {
		id string

		token string

		errCode int
	}{
		{
			id: "ID-1",

			token:   userGoodToken,
			errCode: 0,
		}, {
			id: "NOONE",

			token:   userGoodToken,
			errCode: http.StatusNotFound,
		}, {
			id: "ID-1",

			token:   userBadTokenNotAdmin,
			errCode: http.StatusUnauthorized,
		}, {
			id: "ID-1",

			token:   userBadTokenExpired,
			errCode: http.StatusUnauthorized,
		}, {
			id: "ID-1",

			token:   userBadTokenDisabled,
			errCode: http.StatusUnauthorized,
		}, {
			id: "ID-1",

			token:   "",
			errCode: http.StatusUnauthorized,
		}, {
			id: "ID-1",

			token:   "gibberish",
			errCode: http.StatusUnauthorized,
		},
	}

	for i, tt := range tests {
		func() {
			f := makeUserAPITestFixtures()
			f.trans.Token = tt.token

			defer f.close()
			usr, err := f.client.Users.Get(tt.id).Do()
			if tt.errCode != 0 {
				if err == nil {
					t.Errorf("case %d: err was nil", i)
					return
				}
				gErr, ok := err.(*googleapi.Error)
				if !ok {
					t.Errorf("case %d: not a googleapi Error: %q", i, err)
					return
				}

				if gErr.Code != tt.errCode {
					t.Errorf("case %d: want=%d, got=%d", i, tt.errCode, gErr.Code)
					return
				}
			} else {
				if err != nil {
					t.Errorf("case %d: err != nil: %q", i, err)
					return
				}
				if usr == nil {
					t.Errorf("case %d: user was nil", i)
					return
				}

				if usr.User.Id != "ID-1" {
					t.Errorf("case %d: want=%q, got=%q", i, tt.id, usr.User.Id)
					return
				}
			}
		}()
	}

}

func TestListUsers(t *testing.T) {
	tests := []struct {
		maxResults int64
		pages      int

		token string

		wantCode int
		wantIDs  [][]string
	}{
		{
			pages:      4,
			maxResults: 1,

			token: userGoodToken,

			wantIDs: [][]string{{"ID-1"}, {"ID-2"}, {"ID-3"}, {"ID-4"}},
		},
		{
			pages: 1,

			token: userGoodToken,

			maxResults: 4,
			wantIDs:    [][]string{{"ID-1", "ID-2", "ID-3", "ID-4"}},
		},
		{
			pages: 1,

			token: userBadTokenDisabled,

			maxResults: 1,
			wantCode:   http.StatusUnauthorized, // TODO don't merge until you're sure this is covering what you expect
		},
		{
			pages: 3,

			// make sure that the endpoint is protected, but don't exhaustively
			// try every variation like in TestGetUser
			token: userBadTokenExpired,

			maxResults: 1,
			wantCode:   http.StatusUnauthorized,
		},
		{

			pages: 3,

			token: userGoodToken,

			maxResults: 10000,
			wantCode:   http.StatusBadRequest,
		},
	}

	for i, tt := range tests {
		func() {
			f := makeUserAPITestFixtures()
			defer f.close()
			f.trans.Token = tt.token

			gotIDs := [][]string{}
			var next string
			for x := 0; x < tt.pages; x++ {
				call := f.client.Users.List()
				if next != "" {
					call.NextPageToken(next)
				}
				if tt.maxResults != 0 {
					call.MaxResults(tt.maxResults)
				}
				usersResponse, err := call.Do()

				if tt.wantCode != 0 {
					if err == nil {
						t.Errorf("case %d want non-nil err", i)
						return
					}
					gErr, ok := err.(*googleapi.Error)
					if !ok {
						t.Errorf("case %d: not a googleapi Error: %q %T", i, err, err)
						return
					}

					if gErr.Code != tt.wantCode {
						t.Errorf("case %d: want=%d, got=%d", i, tt.wantCode, gErr.Code)
						return
					}
					return
				}
				if err != nil {
					t.Errorf("case %d: err != nil: %q", i, err)
					return
				}

				var ids []string
				for _, usr := range usersResponse.Users {
					ids = append(ids, usr.Id)
				}
				gotIDs = append(gotIDs, ids)

				next = usersResponse.NextPageToken
			}

			if diff := pretty.Compare(tt.wantIDs, gotIDs); diff != "" {
				t.Errorf("case %d: Compare(want, got) = %v", i,
					diff)
			}
		}()
	}
}

func TestCreateUser(t *testing.T) {
	tests := []struct {
		req       schema.UserCreateRequest
		cantEmail bool

		token string

		wantResponse schema.UserCreateResponse
		wantCode     int
	}{
		{

			req: schema.UserCreateRequest{
				User: &schema.User{
					Email:         "newuser@example.com",
					DisplayName:   "New User",
					EmailVerified: true,
					Admin:         false,
					CreatedAt:     clock.Now().Format(time.RFC3339),
				},
				RedirectURL: testRedirectURL.String(),
			},

			token: userGoodToken,

			wantResponse: schema.UserCreateResponse{
				EmailSent: true,
				User: &schema.User{
					Email:         "newuser@example.com",
					DisplayName:   "New User",
					EmailVerified: true,
					Admin:         false,
					CreatedAt:     clock.Now().Format(time.RFC3339),
				},
			},
		},
		{

			req: schema.UserCreateRequest{
				User: &schema.User{
					Email:         "newuser@example.com",
					DisplayName:   "New User",
					EmailVerified: true,
					Admin:         false,
					CreatedAt:     clock.Now().Format(time.RFC3339),
				},
				RedirectURL: testRedirectURL.String(),
			},
			cantEmail: true,
			token:     userGoodToken,

			wantResponse: schema.UserCreateResponse{
				User: &schema.User{
					Email:         "newuser@example.com",
					DisplayName:   "New User",
					EmailVerified: true,
					Admin:         false,
					CreatedAt:     clock.Now().Format(time.RFC3339),
				},
				ResetPasswordLink: testResetPasswordURL.String(),
			},
		},
		{
			req: schema.UserCreateRequest{
				User: &schema.User{
					Email:         "newuser@example.com",
					DisplayName:   "New User",
					EmailVerified: true,
					Admin:         false,
					CreatedAt:     clock.Now().Format(time.RFC3339),
				},
				RedirectURL: "http://scammers.com",
			},
			token: userGoodToken,

			wantCode: http.StatusBadRequest,
		},
		{

			req: schema.UserCreateRequest{
				User: &schema.User{
					Email:         "newuser@example.com",
					DisplayName:   "New User",
					EmailVerified: true,
					Admin:         false,
					CreatedAt:     clock.Now().Format(time.RFC3339),
				},

				RedirectURL: testRedirectURL.String(),
			},

			// make sure that the endpoint is protected, but don't exhaustively
			// try every variation like in TestGetUser
			token: userBadTokenExpired,

			wantCode: http.StatusUnauthorized,
		},
		{
			req: schema.UserCreateRequest{
				User: &schema.User{
					Email:         "newuser@example.com",
					DisplayName:   "New User",
					EmailVerified: true,
					Admin:         false,
					CreatedAt:     clock.Now().Format(time.RFC3339),
				},
				RedirectURL: testRedirectURL.String(),
			},

			token: userBadTokenDisabled,

			wantCode: http.StatusUnauthorized,
		},
	}
	for i, tt := range tests {
		func() {
			f := makeUserAPITestFixtures()
			defer f.close()
			f.trans.Token = tt.token
			f.emailer.cantEmail = tt.cantEmail

			page, err := f.client.Users.Create(&tt.req).Do()
			if tt.wantCode != 0 {
				if err == nil {
					t.Errorf("case %d: err was nil", i)
					return
				}
				gErr, ok := err.(*googleapi.Error)
				if !ok {
					t.Errorf("case %d: not a googleapi Error: %q", i, err)
					return
				}

				if gErr.Code != tt.wantCode {
					t.Errorf("case %d: want=%d, got=%d", i, tt.wantCode, gErr.Code)
					return
				}
				return
			}

			if err != nil {
				t.Errorf("case %d: want nil err, got: %v %T ", i, err, err)
				return
			}

			newID := page.User.Id
			if newID == "" {
				t.Errorf("case %d: expected non-empty newID", i)
				return
			}

			tt.wantResponse.User.Id = newID
			if diff := pretty.Compare(tt.wantResponse, page); diff != "" {
				t.Errorf("case %d: Compare(want, got) = %v", i,
					diff)
				return
			}

			urlParsed, err := url.Parse(tt.req.RedirectURL)
			if err != nil {
				t.Errorf("case %d unexpected err: %v", i, err)
				return
			}

			wantEmalier := testEmailer{
				cantEmail:       tt.cantEmail,
				lastEmail:       tt.req.User.Email,
				lastClientID:    "XXX",
				lastRedirectURL: *urlParsed,
			}
			if diff := pretty.Compare(wantEmalier, f.emailer); diff != "" {
				t.Errorf("case %d: Compare(want, got) = %v", i,
					diff)
				return
			}

		}()
	}
}

func TestDisableUser(t *testing.T) {
	tests := []struct {
		id      string
		disable bool
	}{
		{
			id:      "ID-2",
			disable: true,
		},
		{
			id:      "ID-4",
			disable: false,
		},
	}

	for i, tt := range tests {
		f := makeUserAPITestFixtures()

		usr, err := f.client.Users.Get(tt.id).Do()
		if err != nil {
			t.Fatalf("case %v: unexpected error: %v", i, err)
		}
		if usr.User.Disabled == tt.disable {
			t.Fatalf("case %v: misconfigured test, initial disabled state should be %v but was %v", i, !tt.disable, usr.User.Disabled)
		}

		_, err = f.client.Users.Disable(tt.id, &schema.UserDisableRequest{
			Disable: tt.disable,
		}).Do()
		if err != nil {
			t.Fatalf("case %v: unexpected error: %v", i, err)
		}
		usr, err = f.client.Users.Get(tt.id).Do()
		if err != nil {
			t.Fatalf("case %v: unexpected error: %v", i, err)
		}
		if usr.User.Disabled != tt.disable {
			t.Errorf("case %v: user disabled state incorrect. wanted: %v found: %v", i, tt.disable, usr.User.Disabled)
		}
	}
}

type testEmailer struct {
	cantEmail       bool
	lastEmail       string
	lastClientID    string
	lastRedirectURL url.URL
}

// SendResetPasswordEmail returns resetPasswordURL when it can't email, mimicking the behavior of the real UserEmailer.
func (t *testEmailer) SendResetPasswordEmail(email string, redirectURL url.URL, clientID string) (*url.URL, error) {
	t.lastEmail = email
	t.lastRedirectURL = redirectURL
	t.lastClientID = clientID

	var retURL *url.URL
	if t.cantEmail {
		retURL = &testResetPasswordURL
	}
	return retURL, nil
}

func makeUserToken(issuerURL url.URL, userID, clientID string, expires time.Duration, privKey *key.PrivateKey) string {

	signer := key.NewPrivateKeySet([]*key.PrivateKey{testPrivKey},
		time.Now().Add(time.Minute)).Active().Signer()
	claims := oidc.NewClaims(issuerURL.String(), userID, clientID, time.Now(), time.Now().Add(expires))
	jwt, err := jose.NewSignedJWT(claims, signer)
	if err != nil {
		panic(fmt.Sprintf("could not make token: %v", err))
	}
	return jwt.Encode()
}
