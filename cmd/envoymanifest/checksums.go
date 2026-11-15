package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
)

// signingKeyFingerprint is the fingerprint of the OpenPGP key that signs
// the checksums.txt.asc file of each Envoy release.
//
// Source: the Envoy repository, which keeps the public key of the Envoy
// maintainers in the file envoy-maintainers-public.key at its root:
//
//	https://github.com/envoyproxy/envoy/blob/main/envoy-maintainers-public.key
//
// The user ID of the key is
// "Envoy maintainers <envoy-maintainers@googlegroups.com>". This command
// prints the fingerprint of the key in a copy of that file:
//
//	gpg --show-keys --with-fingerprint envoy-maintainers-public.key
const signingKeyFingerprint = "0AFCE836BA4D1D35763C8523D8CDC3750181F31F"

var (
	// ErrSigningKey means that the downloaded signing key does not have
	// the pinned fingerprint.
	ErrSigningKey = errors.New("signing key does not have the pinned fingerprint")

	// ErrSignature means that the checksums file does not carry a valid
	// signature of the pinned key.
	ErrSignature = errors.New("checksums signature")
)

// signedChecksums verifies the clearsigned checksums file signed and
// returns its entries as a map from file name to lowercase hex SHA-256.
//
// The file must carry a valid signature of the key in the armored key ring
// key whose primary fingerprint equals fingerprint. The function ignores
// every other key in the key ring. It returns [ErrSigningKey] when the key
// ring does not hold that key and [ErrSignature] when the signature does
// not verify.
func signedChecksums(signed, key []byte, fingerprint string) (map[string]string, error) {
	keys, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(key))
	if err != nil {
		return nil, fmt.Errorf("%w: read key ring: %w", ErrSigningKey, err)
	}

	var pinned openpgp.EntityList

	for _, e := range keys {
		if strings.EqualFold(hex.EncodeToString(e.PrimaryKey.Fingerprint), fingerprint) {
			pinned = append(pinned, e)
		}
	}

	if len(pinned) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrSigningKey, fingerprint)
	}

	// The checksums come only from the signed text of the block, so text
	// outside the block cannot add an entry.
	block, _ := clearsign.Decode(signed)
	if block == nil {
		return nil, fmt.Errorf("%w: no clearsigned message", ErrSignature)
	}

	_, err = block.VerifySignature(pinned, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignature, err)
	}

	sums := make(map[string]string)

	sc := bufio.NewScanner(bytes.NewReader(block.Plaintext))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}

		if len(fields) != 2 {
			return nil, fmt.Errorf("checksums line %q: want a hash and a file name", sc.Text())
		}

		// The sha256sum format marks a file read in binary mode with an
		// asterisk before the name.
		sums[strings.TrimPrefix(fields[1], "*")] = strings.ToLower(fields[0])
	}

	err = sc.Err()
	if err != nil {
		return nil, fmt.Errorf("read checksums: %w", err)
	}

	return sums, nil
}
