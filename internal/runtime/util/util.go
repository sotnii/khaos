package util

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

func CopyMap(src map[string]string) map[string]string {
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func MergeMaps(a, b map[string]string) map[string]string {
	out := CopyMap(a)
	for k, v := range b {
		out[k] = v
	}
	return out
}

func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func NewResourceID() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	var bytes [5]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		panic(fmt.Sprintf("read random bytes: %v", err))
	}

	out := make([]byte, len(bytes))
	for i, b := range bytes {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out)
}
