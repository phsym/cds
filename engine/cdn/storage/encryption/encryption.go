package encryption

import (
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"io"
	"sort"

	"github.com/ovh/cds/engine/cdn/index"
	"github.com/ovh/symmecrypt/convergent"
)

type hashFromHexString string

var _ hash.Hash = new(hashFromHexString)

func (s hashFromHexString) Sum(b []byte) []byte {
	d, _ := hex.DecodeString(string(s))
	return append(b, d[:s.Size()]...)
}
func (s hashFromHexString) Reset() {}
func (s hashFromHexString) Size() int {
	d, _ := hex.DecodeString(string(s))
	return len(d)

}
func (s hashFromHexString) BlockSize() int {
	return sha512.BlockSize
}
func (s hashFromHexString) Write(p []byte) (int, error) {
	return 0, nil
}

type ConvergentEncryption []convergent.ConvergentEncryptionConfig

func (cfg ConvergentEncryption) NewLocator(s string) (string, error) {
	// sort by timestamp: latest (bigger timestamp) first
	sort.Slice(cfg, func(i, j int) bool { return cfg[i].Timestamp > (cfg)[j].Timestamp })
	salt := cfg[0].LocatorSalt
	return convergent.Locator(s, salt)
}

func (cfg ConvergentEncryption) Write(i index.Item, r io.Reader, w io.Writer) error {
	pseudoHash := hashFromHexString(i.Hash)
	return convergent.EncryptTo(r, w, pseudoHash, cfg, []byte(i.ID))
}

func (cfg ConvergentEncryption) Read(i index.Item, r io.Reader, w io.Writer) error {
	pseudoHash := hashFromHexString(i.Hash)
	return convergent.DecryptTo(r, w, pseudoHash, cfg, []byte(i.ID))
}
