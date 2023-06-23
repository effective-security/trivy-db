package vulnsrctest

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

type Updater interface {
	Update(dir string) (err error)
}

type UpdaterFactory func(dbc db.Operation) Updater

type WantValues struct {
	Key   []string
	Value interface{}
}

type TestUpdateArgs struct {
	Dir        string
	WantValues []WantValues
	WantErr    string
	NoBuckets  [][]string
}

func TestUpdate(t *testing.T, vulnsrcf UpdaterFactory, args TestUpdateArgs) {
	t.Helper()

	tempDir := t.TempDir()
	dbPath := db.Path(tempDir)

	// open for update
	dbc, err := db.OpenForUpdate(tempDir)
	require.NoError(t, err)
	defer func() {
		// the second close should not return an error
		assert.NoError(t, dbc.Close())
	}()

	vulnsrc := vulnsrcf(dbc)
	err = vulnsrc.Update(args.Dir)
	if args.WantErr != "" {
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), args.WantErr)
		return
	}
	require.NoError(t, dbc.Close()) // Need to close before dbtest.JSONEq is called

	// open for read
	dbc, err = db.OpenReadonly(tempDir)
	require.NoError(t, err)

	for _, want := range args.WantValues {
		dbtest.JSONEq(t, dbPath, want.Key, want.Value, want.Key)
	}

	for _, noBucket := range args.NoBuckets {
		dbtest.NoBucket(t, dbPath, noBucket, noBucket)
	}
}

type Getter interface {
	Get(string, string) ([]types.Advisory, error)
}

type TestGetArgs struct {
	Fixtures   []string
	WantValues []types.Advisory
	Release    string
	PkgName    string
	WantErr    string
}

func TestGet(t *testing.T, vulnsrc Getter, args TestGetArgs) {
	t.Helper()

	got, err := vulnsrc.Get(args.Release, args.PkgName)

	if args.WantErr != "" {
		require.Error(t, err)
		assert.Contains(t, err.Error(), args.WantErr)
		return
	}

	sort.Slice(got, func(i, j int) bool {
		return got[i].VulnerabilityID < got[j].VulnerabilityID
	})

	assert.NoError(t, err)
	assert.Equal(t, args.WantValues, got)
}
