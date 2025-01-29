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

// WriteJWTBundleSet write the given JWT bundles to disk
func WriteJWTBundleSet(jwkSet *jwtbundle.Set, dir string, jwtBundleFilename string, jwtBundleFileMode fs.FileMode) error {
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

	if err := writeJSON(bundles, dir, jwtBundleFilename, jwtBundleFileMode); err != nil {
		errs = append(errs, fmt.Errorf("unable to write JSON file: %w", err))
	}

	return errors.Join(errs...)
}

// WriteJWTBundle write the given JWT SVID to disk
func WriteJWTSVID(jwtSVIDs []*jwtsvid.SVID, dir, jwtSVIDFilename string, jwtSVIDFileMode fs.FileMode, hint string) error {
	filePath := path.Join(dir, jwtSVIDFilename)
	jwtSVID := getJWTByHint(jwtSVIDs, hint)
	if jwtSVID == nil {
		return fmt.Errorf("failed to find the hinted svid")
	}
	return os.WriteFile(filePath, []byte(jwtSVID.Marshal()), jwtSVIDFileMode)
}

func getJWTByHint(jwtSVIDs []*jwtsvid.SVID, hint string) *jwtsvid.SVID { // Choose a better name :D
	if hint == "" {
		return jwtSVIDs[0]
	}
	for _, jwtSVID := range jwtSVIDs {
		if jwtSVID.Hint == hint {
			return jwtSVID
		}
	}
	return nil
}

func writeJSON(certs map[string]any, dir, filename string, fileMode fs.FileMode) error {
	file, err := json.Marshal(certs)
	if err != nil {
		return err
	}

	filePath := path.Join(dir, filename)

	return os.WriteFile(filePath, file, fileMode)
}
