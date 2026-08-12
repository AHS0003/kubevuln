package v1

import (
	"encoding/json"
	"fmt"

	"github.com/openvex/go-vex/pkg/vex"
)

// ParseExternalOpenVEXDocument parses a raw OpenVEX JSON document (e.g. published by a
// distro or vendor feed such as Red Hat or Chainguard) into a vex.VEX value — the same
// document type kubevuln already produces when generating its own VEX output (see
// repositories/apiserver.go). Each statement is validated per the OpenVEX spec so a
// malformed feed entry surfaces as an error here rather than downstream.
//
// This function does no I/O and no matching against scan results; fetching feeds and
// suppressing findings are separate steps handled elsewhere.
func ParseExternalOpenVEXDocument(raw []byte) (*vex.VEX, error) {
	var doc vex.VEX
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parsing OpenVEX document: %w", err)
	}
	for i, stmt := range doc.Statements {
		if err := stmt.Validate(); err != nil {
			return nil, fmt.Errorf("statement %d invalid: %w", i, err)
		}
	}
	return &doc, nil
}
