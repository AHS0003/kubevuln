package v1

import (
	"os"
	"testing"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseExternalOpenVEXDocument(t *testing.T) {
	tests := []struct {
		name        string
		fixturePath string
		wantErr     bool
		wantStmts   int
	}{
		{
			name:        "valid document with fixed, not_affected and affected statements",
			fixturePath: "testdata/openvex-valid.json",
			wantErr:     false,
			wantStmts:   3,
		},
		{
			name:        "not_affected without justification or impact_statement is rejected",
			fixturePath: "testdata/openvex-missing-justification.json",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := os.ReadFile(tt.fixturePath)
			require.NoError(t, err)

			doc, err := ParseExternalOpenVEXDocument(raw)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "Example Vendor", doc.Author)
			assert.Len(t, doc.Statements, tt.wantStmts)
		})
	}
}

func TestParseExternalOpenVEXDocument_InvalidJSON(t *testing.T) {
	_, err := ParseExternalOpenVEXDocument([]byte(`{not valid json`))
	assert.Error(t, err)
}

func TestParseExternalOpenVEXDocument_StatementValuesPreserved(t *testing.T) {
	raw, err := os.ReadFile("testdata/openvex-valid.json")
	require.NoError(t, err)

	doc, err := ParseExternalOpenVEXDocument(raw)
	require.NoError(t, err)
	require.Len(t, doc.Statements, 3)

	fixed := doc.Statements[0]
	assert.Equal(t, vex.VulnerabilityID("CVE-2023-1255"), fixed.Vulnerability.Name)
	assert.Equal(t, vex.StatusFixed, fixed.Status)
	require.Len(t, fixed.Products, 1)
	assert.Equal(t, "pkg:apk/alpine/openssl@3.1.0-r0", fixed.Products[0].ID)

	notAffected := doc.Statements[1]
	assert.Equal(t, vex.StatusNotAffected, notAffected.Status)
	assert.Equal(t, vex.VulnerableCodeNotPresent, notAffected.Justification)
}
