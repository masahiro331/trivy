package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aquasecurity/trivy/pkg/log"

	fos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"golang.org/x/xerrors"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gorilla/schema"
)

// CycloneDXWriter implements result Writer
type CycloneDXWriter struct {
	Output io.Writer
}

// Write writes the results in CycloneDX format
func (jw CycloneDXWriter) Write(report Report) error {
	var v interface{} = report
	if os.Getenv("TRIVY_NEW_JSON_SCHEMA") == "" {
		// After migrating to the new JSON schema, TRIVY_NEW_JSON_SCHEMA will be removed.
		log.Logger.Warnf("DEPRECATED: the current JSON schema is deprecated, check %s for more information.",
			"https://github.com/aquasecurity/trivy/discussions/1050")
		v = report.Results
	}

	output, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal json: %w", err)
	}

	if _, err = fmt.Fprint(jw.Output, string(output)); err != nil {
		return xerrors.Errorf("failed to write json: %w", err)
	}
	return nil
}

func (r Report) ConvertToBom() (*cdx.BOM, error) {
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Timestamp: time.Now().Format(time.RFC3339),
		Tools: &[]cdx.Tool{
			{
				Vendor:  "aquasecurity",
				Name:    "Trivy",
				Version: "0.17.1",
			},
		},

		// TODO: Support Component section
		// Component: &cdx.Component{}
	}

	libraryMap := map[string]struct{}{}
	componets := []cdx.Component{}

	for _, result := range r.Results {
		component := &cdx.Component{
			Type: TypeToComponent(result.Type),
		}
		componets = append(componets, *component)

		for _, pkg := range result.Packages {
			purl, err := NewPackageUrl(result.Type, pkg)
			if err != nil {
				return nil, xerrors.Errorf("failed to new package url: %w", err)
			}
			libComponent := &cdx.Component{
				Type:       cdx.ComponentTypeLibrary,
				Name:       pkg.Name,
				Version:    pkg.Version,
				PackageURL: purl,
				BOMRef:     purl,
			}
			if _, ok := libraryMap[libComponent.BOMRef]; !ok {
				componets = append(componets, *component)
			}
		}
		result.Packages
	}
	bom.Components = &compoents

	return cdx.BOM{}
}

func NewPackageUrl(t string, pkg types.Package) (string, error) {
	purl := fmt.Sprintf("pkg:%s/%s@%s", t, pkg.Name, pkg.Version)
	qualifiersMap := map[string][]string{}
	if err := schema.NewEncoder().Encode(pkg, qualifiersMap); err != nil {
		return "", xerrors.Errorf("failed to encode qualifiers: %w", err)
	}

	qualifiers := []string{}
	for k, v := range qualifiersMap {
		qualifiers = append(qualifiers, fmt.Sprintf("%s=%s", k, v))
	}
	if len(qualifiers) != 0 {
		purl = fmt.Sprintf("%s?%s", purl, strings.Join(qualifiers, "&"))
	}

	return purl, nil
}

/*
type Package struct {
	Name            string `json:",omitempty"`
	Version         string `json:",omitempty"`
	Release         string `json:",omitempty"`
	Epoch           int    `json:",omitempty"`
	Arch            string `json:",omitempty"`
	SrcName         string `json:",omitempty"`
	SrcVersion      string `json:",omitempty"`
	SrcRelease      string `json:",omitempty"`
	SrcEpoch        int    `json:",omitempty"`
	Modularitylabel string `json:",omitempty"`
	Layer           Layer  `json:",omitempty"`
}
*/

func TypeToComponent(t string) (c cdx.ComponentType) {
	switch t {
	case fos.RedHat, fos.Debian, fos.Ubuntu, fos.CentOS, fos.Fedora, fos.Amazon,
		fos.Oracle, fos.Windows, fos.OpenSUSE, fos.OpenSUSELeap, fos.OpenSUSETumbleweed,
		fos.SLES, fos.Photon, fos.Alpine:
		return cdx.ComponentTypeOS
	default:
		return cdx.ComponentTypeApplication
	}
}
