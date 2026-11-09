package obfs

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const Version = 1

const UpgradeProto = "mantel/1"

var ErrFrame = errors.New("obfs: invalid frame")

func WriteFrame(w io.Writer, packet []byte) error {
	if len(packet) == 0 || len(packet) > MaxFrame {
		return ErrFrame
	}
	frame := make([]byte, 2+len(packet))
	binary.BigEndian.PutUint16(frame, uint16(len(packet)))
	copy(frame[2:], packet)
	_, err := w.Write(frame)
	return err
}

func ReadFrame(r io.Reader, buf []byte) (int, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, err
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size == 0 || size > len(buf) {
		return 0, ErrFrame
	}
	_, err := io.ReadFull(r, buf[:size])
	return size, err
}

func Pin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func PinOfPublicKey(public any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func ValidTokenHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func pinEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func pinMismatch(got string) error {
	return fmt.Errorf("obfs: server key does not match the pin (got %s)", got)
}
