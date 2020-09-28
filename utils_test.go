package filecoin_trustwallet_fixtures

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func privateKeyFromHex(t *testing.T, str string) []byte {
	bin, err := hex.DecodeString(str)
	require.NoError(t, err)
	require.Len(t, bin, 32)
	return bin
}
