package version

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersion(t *testing.T) {
	oldGittag := gittag
	oldGithash := githash
	defer func() {
		gittag = oldGittag
		githash = oldGithash
	}()

	tests := []struct {
		name     string
		gittag   string
		githash  string
		expected string
	}{
		{
			name:     "gittag is set",
			gittag:   "v1.0.0",
			githash:  "abcdef123",
			expected: "v1.0.0",
		},
		{
			name:     "gittag is empty",
			gittag:   "",
			githash:  "abcdef123",
			expected: fmt.Sprintf("%s-dev-abcdef123", Base),
		},
		{
			name:     "gittag is empty and githash is unk",
			gittag:   "",
			githash:  "unk",
			expected: fmt.Sprintf("%s-dev-unk", Base),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gittag = tt.gittag
			githash = tt.githash
			assert.Equal(t, tt.expected, Version())
		})
	}
}
