package pkg

import (
	"github.com/urfave/cli"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/vulndb"
)

func build(c *cli.Context) error {
	cacheDir := c.String("cache-dir")
	dbc, err := db.OpenForUpdate(cacheDir)
	if err != nil {
		return xerrors.Errorf("db initialize error: %w", err)
	}
	defer dbc.Close()

	targets := c.StringSlice("only-update")
	updateInterval := c.Duration("update-interval")

	vdb := vulndb.New(dbc, cacheDir, updateInterval)
	if err := vdb.Build(targets); err != nil {
		return xerrors.Errorf("build error: %w", err)
	}

	return nil

}
