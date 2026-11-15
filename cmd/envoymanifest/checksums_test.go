package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newKey returns a new OpenPGP key pair.
func newKey(t *testing.T) *openpgp.Entity {
	t.Helper()

	key, err := openpgp.NewEntity("Test maintainers", "", "test@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoEdDSA,
	})
	require.NoError(t, err)

	return key
}

// fingerprintOf returns the hex fingerprint of the primary key of key.
func fingerprintOf(key *openpgp.Entity) string {
	return hex.EncodeToString(key.PrimaryKey.Fingerprint)
}

// armoredKeys returns an armored key ring that holds the public keys of
// keys.
func armoredKeys(t *testing.T, keys ...*openpgp.Entity) []byte {
	t.Helper()

	var buf bytes.Buffer

	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	require.NoError(t, err)

	for _, key := range keys {
		require.NoError(t, key.Serialize(w))
	}

	require.NoError(t, w.Close())

	return buf.Bytes()
}

// clearsigned returns text as a clearsigned message with a signature of
// signer.
func clearsigned(t *testing.T, signer *openpgp.Entity, text string) []byte {
	t.Helper()

	var buf bytes.Buffer

	w, err := clearsign.Encode(&buf, signer.PrivateKey, nil)
	require.NoError(t, err)

	_, err = w.Write([]byte(text))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	return buf.Bytes()
}

// TestSignedChecksumsEnvoyRelease checks the checksums.txt.asc file of the
// Envoy v1.40.2 release against the key file of the Envoy repository. It
// shows that [signingKeyFingerprint] is the fingerprint of that key.
func TestSignedChecksumsEnvoyRelease(t *testing.T) {
	t.Parallel()

	signed, err := os.ReadFile(filepath.Join("testdata", "envoy-v1.40.2-checksums.txt"))
	require.NoError(t, err)

	key, err := os.ReadFile(filepath.Join("testdata", "envoy-maintainers-public-key.txt"))
	require.NoError(t, err)

	got, err := signedChecksums(signed, key, signingKeyFingerprint)
	require.NoError(t, err)

	assert.Equal(t, map[string]string{
		"debs.tar.gz":                         "8f3bf0a659d0d6596beacced6b48794da4e67024f542941c94d1fdf367026452",
		"envoy-1.40.2-linux-x86_64":           "1d64506e25c1844f146162ddb2ece7010fa4e784faddb40a079021491f1f03cc",
		"envoy-contrib-1.40.2-linux-x86_64":   "4fcda3d480acd6124c8a85487d79992b00f2e008cab25532ae28be764a92cdaa",
		"envoy-1.40.2-linux-aarch_64":         "b9d6d1e06dd5838a3506de9f4deebad3de9a2ce6cadb87cd76222ca286213baf",
		"envoy-contrib-1.40.2-linux-aarch_64": "87120d0f5ee5f885bd9dfb92d7ea78a75e7f02c9faed9e129a25c77c4c64d30f",
	}, got)

	// One changed character in the signed text breaks the signature.
	tampered := bytes.Replace(signed, []byte("1d64506e"), []byte("2d64506e"), 1)
	require.NotEqual(t, signed, tampered)

	_, err = signedChecksums(tampered, key, signingKeyFingerprint)
	require.ErrorIs(t, err, ErrSignature)
}

func TestSignedChecksums(t *testing.T) {
	t.Parallel()

	pinned := newKey(t)
	other := newKey(t)

	const text = "aa11  envoy-linux\nBB22 *envoy-other\n\n"

	signed := clearsigned(t, pinned, text)

	tests := map[string]struct {
		err    error
		want   map[string]string
		msg    string
		signed []byte
		key    []byte
	}{
		"signature of the pinned key": {
			signed: signed,
			key:    armoredKeys(t, pinned),
			want:   map[string]string{"envoy-linux": "aa11", "envoy-other": "bb22"},
		},
		"key ring holds another key before the pinned key": {
			signed: signed,
			key:    armoredKeys(t, other, pinned),
			want:   map[string]string{"envoy-linux": "aa11", "envoy-other": "bb22"},
		},
		"text outside the signed message": {
			signed: append([]byte("cc33  envoy-linux\n"), append(signed, []byte("dd44  envoy-linux\n")...)...),
			key:    armoredKeys(t, pinned),
			want:   map[string]string{"envoy-linux": "aa11", "envoy-other": "bb22"},
		},
		"text changed after signing": {
			signed: bytes.Replace(signed, []byte("aa11"), []byte("aa12"), 1),
			key:    armoredKeys(t, pinned),
			err:    ErrSignature,
		},
		"signature of another key": {
			signed: clearsigned(t, other, text),
			key:    armoredKeys(t, pinned),
			err:    ErrSignature,
		},
		"signature of another key that the key ring holds": {
			signed: clearsigned(t, other, text),
			key:    armoredKeys(t, other, pinned),
			err:    ErrSignature,
		},
		"key ring without the pinned key": {
			signed: clearsigned(t, other, text),
			key:    armoredKeys(t, other),
			err:    ErrSigningKey,
		},
		"key is not armored": {
			signed: signed,
			key:    []byte("not a key"),
			err:    ErrSigningKey,
		},
		"checksums without a signature": {
			signed: []byte(text),
			key:    armoredKeys(t, pinned),
			err:    ErrSignature,
			msg:    "no clearsigned message",
		},
		"line with three fields": {
			signed: clearsigned(t, pinned, "aa11  envoy linux\n"),
			key:    armoredKeys(t, pinned),
			msg:    `checksums line "aa11  envoy linux"`,
		},
		"line longer than the scanner buffer": {
			signed: clearsigned(t, pinned, strings.Repeat("a", 70_000)+"\n"),
			key:    armoredKeys(t, pinned),
			msg:    "read checksums",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := signedChecksums(tc.signed, tc.key, fingerprintOf(pinned))

			if tc.err != nil || tc.msg != "" {
				require.Error(t, err)

				if tc.err != nil {
					require.ErrorIs(t, err, tc.err)
				}

				require.ErrorContains(t, err, tc.msg)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
