package storage_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"io/ioutil"
	"testing"
	"time"

	"github.com/ovh/cds/engine/cdn/index"
	_ "github.com/ovh/cds/engine/cdn/storage/local"
	_ "github.com/ovh/cds/engine/cdn/storage/redis"
	"github.com/ovh/symmecrypt/ciphers/aesgcm"
	"github.com/ovh/symmecrypt/convergent"

	"github.com/ovh/cds/engine/api/test"
	commontest "github.com/ovh/cds/engine/test"

	"github.com/ovh/cds/engine/cdn/storage"
	"github.com/ovh/cds/engine/gorpmapper"
	"github.com/ovh/cds/sdk"
	"github.com/stretchr/testify/require"
)

func TestRun(t *testing.T) {
	m := gorpmapper.New()
	index.InitDBMapping(m)
	storage.InitDBMapping(m)

	db, _ := test.SetupPGWithMapper(t, m, sdk.TypeCDN)
	cfg := commontest.LoadTestingConf(t, sdk.TypeCDN)

	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()

	tmpDir, err := ioutil.TempDir("", t.Name()+"-cdn-*")
	require.NoError(t, err)
	tmpDir2, err := ioutil.TempDir("", t.Name()+"-cdn-*")
	require.NoError(t, err)

	cdnUnits, err := storage.Init(ctx, m, db.DbMap, storage.Configuration{
		Buffer: storage.BufferConfiguration{
			Name: "redis_buffer",
			Redis: storage.RedisBufferConfiguration{
				Host:     cfg["redisHost"],
				Password: cfg["redisPassword"],
			},
		},
		Storages: []storage.StorageConfiguration{
			{
				Name:     "local_storage",
				CronExpr: "* * * * * ?",
				Local: &storage.LocalStorageConfiguration{
					Path: tmpDir,
					Encryption: []convergent.ConvergentEncryptionConfig{
						{
							Cipher:      aesgcm.CipherName,
							LocatorSalt: "secret_locator_salt",
							SecretValue: "secret_value",
						},
					},
				},
			}, {
				Name:     "local_storage_2",
				CronExpr: "* * * * * ?",
				Local: &storage.LocalStorageConfiguration{
					Path: tmpDir2,
					Encryption: []convergent.ConvergentEncryptionConfig{
						{
							Cipher:      aesgcm.CipherName,
							LocatorSalt: "secret_locator_salt_2",
							SecretValue: "secret_value_2",
						},
					},
				},
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, cdnUnits)

	units, err := storage.LoadAllUnits(ctx, m, db.DbMap)
	require.NoError(t, err)
	require.NotNil(t, units)
	require.NotEmpty(t, units)

	apiRef := index.ApiRef{
		ProjectKey: sdk.RandomString(5),
	}

	apiRefHash, err := index.ComputeApiRef(apiRef)
	require.NoError(t, err)

	i := index.Item{
		ID:         sdk.UUID(),
		ApiRef:     apiRef,
		ApiRefHash: apiRefHash,
		Created:    time.Now(),
	}
	require.NoError(t, index.InsertItem(ctx, m, db, &i))
	require.NoError(t, cdnUnits.Buffer.Add(i, 1.0, "this is the first log"))
	require.NoError(t, cdnUnits.Buffer.Add(i, 1.0, "this is the second log"))

	redisUnit, err := storage.LoadUnitByName(ctx, m, db, "redis_buffer")
	require.NoError(t, err)

	reader, err := cdnUnits.Buffer.NewReader(i)
	require.NoError(t, err)

	h, err := convergent.NewHash(reader)
	require.NoError(t, err)
	i.Hash = hex.EncodeToString(h.Sum(nil))

	err = index.UpdateItem(ctx, m, db, &i)
	require.NoError(t, err)

	var itemUnit = &storage.ItemUnit{
		ItemID:       i.ID,
		UnitID:       redisUnit.ID,
		LastModified: time.Now(),
	}

	err = storage.InsertItemUnit(ctx, m, db, itemUnit)
	require.NoError(t, err)

	localUnit, err := storage.LoadUnitByName(ctx, m, db, "local_storage")
	require.NoError(t, err)

	localUnit2, err := storage.LoadUnitByName(ctx, m, db, "local_storage_2")
	require.NoError(t, err)

	localUnitDriver := cdnUnits.Storage(localUnit.Name)
	require.NotNil(t, localUnitDriver)

	localUnitDriver2 := cdnUnits.Storage(localUnit2.Name)
	require.NotNil(t, localUnitDriver)

	exists, err := localUnitDriver.ItemExists(i)
	require.NoError(t, err)
	require.False(t, exists)

	<-ctx.Done()

	i2, err := index.LoadItemByID(ctx, m, db, i.ID, gorpmapper.GetOptions.WithDecryption)
	require.NoError(t, err)

	// Check that the first unit has been resync

	exists, err = localUnitDriver.ItemExists(*i2)
	require.NoError(t, err)
	require.True(t, exists)

	exists, err = localUnitDriver2.ItemExists(*i2)
	require.NoError(t, err)
	require.True(t, exists)

	reader, err = localUnitDriver.NewReader(*i2)
	btes := new(bytes.Buffer)
	err = localUnitDriver.Read(*i2, reader, btes)
	require.NoError(t, err)

	require.NoError(t, reader.Close())

	actual := btes.String()
	require.Equal(t, `this is the first log
this is the second log`, actual)

	itemIDs, err := storage.LoadAllItemIDUnknownByUnit(ctx, m, db, localUnitDriver.ID(), 5)
	require.NoError(t, err)
	require.Len(t, itemIDs, 0)

	// Check that the second unit has been resync

	reader, err = localUnitDriver2.NewReader(*i2)
	btes = new(bytes.Buffer)
	err = localUnitDriver2.Read(*i2, reader, btes)
	require.NoError(t, err)

	require.NoError(t, reader.Close())

	actual = btes.String()
	require.Equal(t, `this is the first log
this is the second log`, actual)

	itemIDs, err = storage.LoadAllItemIDUnknownByUnit(ctx, m, db, localUnitDriver2.ID(), 5)
	require.NoError(t, err)
	require.Len(t, itemIDs, 0)

}
