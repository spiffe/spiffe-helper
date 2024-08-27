package disk

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

// WriteJWTBundleSet write the given JWT bundles to disk
func WriteJWTBundleSet(jwkSet *jwtbundle.Set, dir string, jwtBundleFilename string) error {
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

	if err := writeJSON(bundles, dir, jwtBundleFilename); err != nil {
		errs = append(errs, fmt.Errorf("unable to write JSON file: %w", err))
	}

	return errors.Join(errs...)
}

// WriteJWTBundle write the given JWT SVID to disk
func WriteJWTSVID(jwtSVID *jwtsvid.SVID, dir, jwtSVIDFilename string) error {
	filePath := path.Join(dir, jwtSVIDFilename)

	return os.WriteFile(filePath, []byte(jwtSVID.Marshal()), 0600)
}

func writeJSON(certs map[string]any, dir, filename string) error {
	file, err := json.Marshal(certs)
	if err != nil {
		return err
	}

	filePath := path.Join(dir, filename)

	return os.WriteFile(filePath, file, 0600)
}
