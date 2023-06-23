package alpine_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alpine"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		wantErr    string
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "alpine 3.12"},
					Value: types.DataSource{
						ID:   vulnerability.Alpine,
						Name: "Alpine Secdb",
						URL:  "https://secdb.alpinelinux.org/",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2019-14904", "alpine 3.12", "ansible"},
					Value: types.Advisory{
						FixedVersion: "2.9.3-r0",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2019-14905", "alpine 3.12", "ansible"},
					Value: types.Advisory{
						FixedVersion: "2.9.3-r0",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-1737", "alpine 3.12", "ansible"},
					Value: types.Advisory{
						FixedVersion: "2.9.6-r0",
					},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode Alpine advisory",
		},
	}
	f := func(dbc db.Operation) vulnsrctest.Updater {
		return alpine.NewVulnSrc(dbc)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulnsrctest.TestUpdate(t, f, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
