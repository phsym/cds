package webdav

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/ovh/cds/engine/cdn/storage"
	"github.com/ovh/cds/sdk/log"
	"github.com/ovh/symmecrypt/ciphers/aesgcm"
	"github.com/ovh/symmecrypt/convergent"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/webdav"
)

func TestWebdav(t *testing.T) {
	log.SetLogger(t)
	dir, err := ioutil.TempDir("", t.Name()+"-cdn-webdav-*")
	require.NoError(t, err)
	srv := &webdav.Handler{
		FileSystem: webdav.Dir(dir),
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			if err != nil {
				t.Logf("WEBDAV [%s]: %s, ERROR: %s\n", r.Method, r.URL, err)
			} else {
				t.Logf("WEBDAV [%s]: %s \n", r.Method, r.URL)
			}
		},
	}
	http.Handle("/", srv)
	go func() {
		if err := http.ListenAndServe(fmt.Sprintf(":%d", 8091), nil); err != nil {
			log.Fatalf("Error with WebDAV server: %v", err)
		}
	}()

	var driver = new(Webdav)
	err = driver.Init(&storage.WebdavStorageConfiguration{
		Address:  "http://localhost:8091",
		Username: "username",
		Password: "password",
		Path:     "data",
		Encryption: []convergent.ConvergentEncryptionConfig{
			{
				Cipher:      aesgcm.CipherName,
				LocatorSalt: "secret_locator_salt",
				SecretValue: "secret_value",
			},
		},
	})
	require.NoError(t, err, "unable to initialiaze webdav driver")

	itemUnit := storage.ItemUnit{
		Locator: "a_locator",
	}
	w, err := driver.NewWriter(itemUnit)
	require.NoError(t, err)
	require.NotNil(t, w)

	_, err = w.Write([]byte("something"))
	require.NoError(t, err)

	err = w.Close()
	require.NoError(t, err)

	r, err := driver.NewReader(itemUnit)
	require.NoError(t, err)
	require.NotNil(t, r)

	btes, err := ioutil.ReadAll(r)
	require.NoError(t, err)
	err = r.Close()
	require.NoError(t, err)

	require.Equal(t, "something", string(btes))
}
