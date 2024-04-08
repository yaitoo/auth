package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAES(t *testing.T) {
	key := getAESKey(randLetters(5))

	src := randLetters(10)

	cipherText, err := encryptText([]byte(src), key)
	require.NoError(t, err)

	plainText, err := decryptText(cipherText, key)
	require.NoError(t, err)
	require.Equal(t, src, plainText)
}
