package user

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/key"
	"github.com/coreos/go-oidc/oidc"

	"github.com/coreos/dex/repo"
)

var (
	ErrorSSHNoSignatureMatch = errors.New("signature does not match challenge for any registered public keys")
)

type SSHIdentity struct {
	UserID     string
	PublicKeys []string
}

func (p SSHIdentity) Authenticate(plaintext string) (*oidc.Identity, error) {
	// expected format: $format.$base64sig
	strs := strings.Split(plaintext, ".")
	sigData, err := base64.StdEncoding.DecodeString(strs[1])
	if err != nil {
		return err
	}

	sig := &ssh.Signature{strs[0], sigData}

	ok := false
	for _, k := range p.PublicKeys {
		mKey := k.Marshal()
		key, _, _, err := ssh.ParseAuthorizedKey(k)
		if err != nil {
			return err
		}
		err = key.Verify(data, sig)
		if err == nil {
			ok = true
			break
		}
	}

	if !ok {
		return nil, ErrorSSHNoSignatureMatch
	}

	ident := p.Identity()
	return &ident, nil
}

func (p SSHIdentity) Identity() oidc.Identity {
	return oidc.Identity{
		ID: p.UserID,
	}
}

type SSHIdentityRepo interface {
	Get(tx repo.Transaction, id string) (SSHIdentity, error)
	Update(repo.Transaction, SSHIdentity) error
	Create(repo.Transaction, SSHIdentity) error
}

func NewSSHIdentityRepo() SSHIdentityRepo {
	return &memSSHIdentityRepo{
		ids: make(map[string]SSHIdentity),
	}
}

type memSSHIdentityRepo struct {
	ids map[string]SSHIdentity
}

func (m *memSSHIdentityRepo) Get(_ repo.Transaction, id string) (SSHIdentity, error) {
	sid, ok := m.ids[id]
	if !ok {
		return SSHIdentity{}, ErrorNotFound
	}
	return sid, nil
}

func (m *memSSHIdentityRepo) Create(_ repo.Transaction, id SSHIdentity) error {
	_, ok := m.ids[id.UserID]
	if ok {
		return ErrorDuplicateID
	}

	if id.UserID == "" {
		return ErrorInvalidID
	}

	if len(id.PublicKeys) == 0 {
		return ErrorNoPublicKeys
	}

	m.ids[id.UserID] = id
	return nil
}

func (m *memSSHIdentityRepo) Update(_ repo.Transaction, id SSHIdentity) error {
	if id.UserID == "" {
		return ErrorInvalidID
	}

	_, ok := m.ids[id.UserID]
	if !ok {
		return ErrorNotFound
	}

	if len(id.PublicKeys) == 0 {
		return ErrorNoPublicKeys
	}

	m.ids[id.UserID] = id
	return nil
}

func (u *SSHIdentity) UnmarshalJSON(data []byte) error {
	var dec struct {
		UserID            string    `json:"userId"`
		PasswordHash      string    `json:"passwordHash"`
		PasswordPlaintext string    `json:"passwordPlaintext"`
		PasswordExpires   time.Time `json:"passwordExpires"`
	}

	err := json.Unmarshal(data, &dec)
	if err != nil {
		return fmt.Errorf("invalid User entry: %v", err)
	}

	u.UserID = dec.UserID

	u.PasswordExpires = dec.PasswordExpires

	if len(dec.PasswordHash) != 0 {
		if dec.PasswordPlaintext != "" {
			return ErrorInvalidPassword
		}
		u.Password = Password(dec.PasswordHash)
		return nil
	}
	if dec.PasswordPlaintext != "" {
		u.Password, err = NewPasswordFromPlaintext(dec.PasswordPlaintext)
		if err != nil {
			return err
		}
	}
	return nil
}

func newSSHIdentitysFromReader(r io.Reader) ([]SSHIdentity, error) {
	var ids []SSHIdentity
	err := json.NewDecoder(r).Decode(&ids)
	return ids, err
}

func readSSHIdentitysFromFile(loc string) ([]SSHIdentity, error) {
	idf, err := os.Open(loc)
	if err != nil {
		return nil, fmt.Errorf("unable to read password info from file %q: %v", loc, err)
	}

	return newSSHIdentitysFromReader(idf)
}

func LoadSSHIdentitys(repo SSHIdentityRepo, ids []SSHIdentity) error {
	for i, id := range ids {
		err := repo.Create(nil, id)
		if err != nil {
			return fmt.Errorf("error loading SSHIdentity[%d]: %q", i, err)
		}
	}
	return nil
}

func NewSSHIdentityRepoFromSSHIdentitys(ids []SSHIdentity) SSHIdentityRepo {
	memRepo := NewSSHIdentityRepo().(*memSSHIdentityRepo)
	for _, id := range ids {
		memRepo.ids[id.UserID] = id
	}
	return memRepo
}

func NewSSHIdentityRepoFromFile(loc string) (SSHIdentityRepo, error) {
	ids, err := readSSHIdentitysFromFile(loc)
	if err != nil {
		return nil, err
	}

	return NewSSHIdentityRepoFromSSHIdentitys(ids), nil
}
