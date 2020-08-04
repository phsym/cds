package local

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ovh/cds/engine/cdn/index"
	"github.com/ovh/cds/engine/cdn/storage"
	"github.com/ovh/cds/engine/cdn/storage/encryption"
	"github.com/ovh/cds/sdk"
)

type Local struct {
	storage.AbstractUnit
	encryption.ConvergentEncryption
	config storage.LocalStorageConfiguration
}

var _ storage.StorageUnit = new(Local)

func init() {
	storage.RegisterDriver("local", new(Local))
}

func (s *Local) Init(cfg interface{}) error {
	config, is := cfg.(*storage.LocalStorageConfiguration)
	if !is {
		return sdk.WithStack(fmt.Errorf("invalid configuration: %T", cfg))
	}
	s.config = *config
	s.ConvergentEncryption = config.Encryption
	return os.MkdirAll(s.config.Path, os.FileMode(0755))
}

func (s *Local) filename(i index.Item) (string, error) {
	loc, err := s.NewLocator(i.Hash)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.config.Path, loc), nil
}

func (s *Local) ItemExists(i index.Item) (bool, error) {
	// Lookup on the filesystem according to the locator
	path, err := s.filename(i)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(path)
	return !os.IsNotExist(err), nil
}

func (s *Local) NewWriter(i index.Item) (io.WriteCloser, error) {
	// Open the file from the filesystem according to the locator
	path, err := s.filename(i)
	if err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR, os.FileMode(0644))
}
func (s *Local) NewReader(i index.Item) (io.ReadCloser, error) {
	// Open the file from the filesystem according to the locator
	path, err := s.filename(i)
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}
