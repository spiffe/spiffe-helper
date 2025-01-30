package disk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/fs"
	"os"
	"path"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/cryptosigner"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/stretchr/testify/require"
)

const (
	jwtBundleFilename = "jwt_bundle.json"
	jwtSVIDFilename   = "jwt.json"
	jwtBundleFileMode = fs.FileMode(0600)
	jwtSVIDFileMode   = fs.FileMode(0600)
)

func TestWriteJWTBundleSet(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.test")

	jwtBundle := jwtbundle.New(td)
	jwtBundleSet := jwtbundle.NewSet(jwtBundle)

	tempDir := t.TempDir()

	err := WriteJWTBundleSet(jwtBundleSet, tempDir, jwtBundleFilename, jwtBundleFileMode)
	require.NoError(t, err)

	actualJWTBundle, err := jwtbundle.Load(td, path.Join(tempDir, jwtBundleFilename))
	require.NoError(t, err)
	require.Equal(t, jwtBundle, actualJWTBundle)
}

func TestWriteJWTSVIDNoHint(t *testing.T) {
	spiffeID := spiffeid.RequireFromString("spiffe://example.test/workload")

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	// Generate Token
	claims := jwt.Claims{
		Subject:  spiffeID.String(),
		Issuer:   "issuer",
		Expiry:   jwt.NewNumericDate(time.Now()),
		Audience: []string{"audience"},
		IssuedAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
	}
	token := generateToken(t, claims, key, "key")

	// Create SVID
	jwtSVID, err := jwtsvid.ParseInsecure(token, []string{"audience"})
	require.NoError(t, err)

	// Create SVID array
	jwtSVIDs := []*jwtsvid.SVID{jwtSVID}

	// Write to disk
	tempDir := t.TempDir()
	err = WriteJWTSVID(jwtSVIDs, tempDir, jwtSVIDFilename, jwtSVIDFileMode, "")
	require.NoError(t, err)

	// Read back and check it's the same
	actualToken, err := os.ReadFile(path.Join(tempDir, jwtSVIDFilename))
	require.NoError(t, err)
	require.Equal(t, token, string(actualToken))
}

func TestWriteJWTSVIDWithHint(t *testing.T) {
	spiffeID := spiffeid.RequireFromString("spiffe://example.test/workload")

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	// Generate Token
	claims := jwt.Claims{
		Subject:  spiffeID.String(),
		Issuer:   "issuer",
		Expiry:   jwt.NewNumericDate(time.Now()),
		Audience: []string{"audience"},
		IssuedAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
	}
	token := generateToken(t, claims, key, "key")

	// Create SVID
	jwtSVID, err := jwtsvid.ParseInsecure(token, []string{"audience"})
	jwtSVID.Hint = "first"
	require.NoError(t, err)

	// Generate Token2
	claims = jwt.Claims{
		Subject:  spiffeID.String(),
		Issuer:   "issuer",
		Expiry:   jwt.NewNumericDate(time.Now()),
		Audience: []string{"audience"},
		IssuedAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
	}
	token = generateToken(t, claims, key, "key")

	// Create SVID
	jwtSVID2, err := jwtsvid.ParseInsecure(token, []string{"audience"})
	jwtSVID2.Hint = "other"
	require.NoError(t, err)

	// Create SVID array
	jwtSVIDs := []*jwtsvid.SVID{jwtSVID, jwtSVID2}

	// Write to disk
	tempDir := t.TempDir()
	err = WriteJWTSVID(jwtSVIDs, tempDir, jwtSVIDFilename, jwtSVIDFileMode, "other")
	require.NoError(t, err)

	// Read back and check it's the same
	actualToken, err := os.ReadFile(path.Join(tempDir, jwtSVIDFilename))
	require.NoError(t, err)
	require.Equal(t, token, string(actualToken))
}

// Generate generates a signed string token
func generateToken(tb testing.TB, claims jwt.Claims, signer crypto.Signer, keyID string) string {
	// Get signer algorithm
	alg, err := getSignerAlgorithm(signer)
	require.NoError(tb, err)

	// Create signer using crypto.Signer and its algorithm along with provided key ID
	jwtSigner, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: alg,
			Key: jose.JSONWebKey{
				Key:   cryptosigner.Opaque(signer),
				KeyID: keyID,
			},
		},
		new(jose.SignerOptions).WithType("JWT"),
	)
	require.NoError(tb, err)

	// Sign and serialize token
	token, err := jwt.Signed(jwtSigner).Claims(claims).CompactSerialize()
	require.NoError(tb, err)

	return token
}

// getSignerAlgorithm deduces signer algorithm and return it
func getSignerAlgorithm(signer crypto.Signer) (jose.SignatureAlgorithm, error) {
	switch publicKey := signer.Public().(type) {
	case *rsa.PublicKey:
		// Prevent the use of keys smaller than 2048 bits
		if publicKey.Size() < 256 {
			return "", fmt.Errorf("unsupported RSA key size: %d", publicKey.Size())
		}
		return jose.RS256, nil
	case *ecdsa.PublicKey:
		params := publicKey.Params()
		switch params.BitSize {
		case 256:
			return jose.ES256, nil
		case 384:
			return jose.ES384, nil
		default:
			return "", fmt.Errorf("unable to determine signature algorithm for EC public key size %d", params.BitSize)
		}
	default:
		return "", fmt.Errorf("unable to determine signature algorithm for public key type %T", publicKey)
	}
}
