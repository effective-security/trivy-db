package vulnsrc

import (
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alma"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alpine"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/amazon"
	archlinux "github.com/aquasecurity/trivy-db/pkg/vulnsrc/arch-linux"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bundler"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/chainguard"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/composer"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/debian"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ghsa"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/glad"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/k8svulndb"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/mariner"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/node"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/nvd"
	oracleoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/oracle-oval"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/photon"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat"
	redhatoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat-oval"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/rocky"
	susecvrf "github.com/aquasecurity/trivy-db/pkg/vulnsrc/suse-cvrf"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ubuntu"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/wolfi"
)

type VulnSrc interface {
	Name() types.SourceID
	Update(dir string) (err error)
}

func All(dbc db.Operation) []VulnSrc {

	// All holds all data sources
	return []VulnSrc{
		// NVD
		nvd.NewVulnSrc(dbc),

		// OS packages
		alma.NewVulnSrc(dbc),
		alpine.NewVulnSrc(dbc),
		archlinux.NewVulnSrc(dbc),
		redhat.NewVulnSrc(dbc),
		redhatoval.NewVulnSrc(dbc),
		debian.NewVulnSrc(dbc),
		ubuntu.NewVulnSrc(dbc),
		amazon.NewVulnSrc(dbc),
		oracleoval.NewVulnSrc(dbc),
		rocky.NewVulnSrc(dbc),
		susecvrf.NewVulnSrc(dbc, susecvrf.SUSEEnterpriseLinux),
		susecvrf.NewVulnSrc(dbc, susecvrf.OpenSUSE),
		photon.NewVulnSrc(dbc),
		mariner.NewVulnSrc(dbc),
		wolfi.NewVulnSrc(dbc),
		chainguard.NewVulnSrc(dbc),

		k8svulndb.NewVulnSrc(dbc),
		// Language-specific packages
		bundler.NewVulnSrc(dbc),
		composer.NewVulnSrc(dbc),
		node.NewVulnSrc(dbc),
		ghsa.NewVulnSrc(dbc),
		glad.NewVulnSrc(dbc),
		//osv.NewVulnSrc(dbc),
	}
}
