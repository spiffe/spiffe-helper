package disk

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

type JWTConfig struct {
	Dir            string
	BundleFileName string
	BundleFileMode fs.FileMode
	SVIDFileMode   fs.FileMode
	Hint           string
}

type JWT struct {
	c JWTConfig
}

func NewJWT(c JWTConfig) *JWT {
	return &JWT{
		c: c,
	}
}

// WriteJWTBundleSet write the given JWT bundles to disk
func (j *JWT) WriteJWTBundleSet(jwkSet *jwtbundle.Set) error {
	var errs []error
	bundles := make(map[string]interface{})
	for _, bundle := range jwkSet.Bundles() {
		bytes, err := bundle.Marshal()
		if err != nil {
			errs = append(errs, fmt.Errorf("unable to marshal JWT bundle: %w", err))
			continue
		}
		bundles[bundle.TrustDomain().Name()] = base64.StdEncoding.EncodeToString(bytes)
	}

	if err := j.writeJSON(bundles); err != nil {
		errs = append(errs, fmt.Errorf("unable to write JSON file: %w", err))
	}

	return errors.Join(errs...)
}

// WriteJWTSVID write the given JWT SVID to disk
func (j *JWT) WriteJWTSVID(jwtSVIDs []*jwtsvid.SVID, fileName string) error {
	jwtSVID, err := j.getJWTSVID(jwtSVIDs)
	if err != nil {
		return err
	}

	jwtSVIDMarshaled := []byte(jwtSVID.Marshal())
	filePath := path.Join(j.c.Dir, fileName)

	return os.WriteFile(filePath, jwtSVIDMarshaled, j.c.SVIDFileMode)
}

func (j *JWT) BundlePath() string {
	return path.Join(j.c.Dir, j.c.BundleFileName)
}

func (j *JWT) BundleEnabled() bool {
	return j.c.BundleFileName != ""
}

func (j *JWT) SVIDPath(filename string) string {
	return path.Join(j.c.Dir, filename)
}

// writeJSON write the JSON bundle to disk
func (j *JWT) writeJSON(certs map[string]any) error {
	file, err := json.Marshal(certs)
	if err != nil {
		return err
	}

	filePath := path.Join(j.c.Dir, j.c.BundleFileName)

	return os.WriteFile(filePath, file, j.c.BundleFileMode)
}

// getJWTSVID extracts the JWT SVID that matches the hint or returns the default
// if hint is empty
func (j *JWT) getJWTSVID(jwtSVIDs []*jwtsvid.SVID) (*jwtsvid.SVID, error) {
	if j.c.Hint == "" {
		return jwtSVIDs[0], nil
	}
	for _, jwtSVID := range jwtSVIDs {
		if jwtSVID.Hint == j.c.Hint {
			return jwtSVID, nil
		}
	}

	return nil, fmt.Errorf("failed to find the hinted JWT SVID")
}
