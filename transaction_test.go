package filecoin_trustwallet_fixtures

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/crypto"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/filecoin-project/lotus/lib/sigs"
	_ "github.com/filecoin-project/lotus/lib/sigs/secp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilecoinSigner_DerivePublicKey(t *testing.T) {
	privateKey := privateKeyFromHex(t, "1d969865e189957b9824bd34f26d5cbf357fda1a6d844cbf0c9ab1ed93fa7dbe")
	publicKey, err := sigs.ToPublic(crypto.SigTypeSecp256k1, privateKey)
	require.NoError(t, err)
	addr, err := address.NewSecp256k1Address(publicKey)
	require.NoError(t, err)
	assert.Equal(t, "t1z4a36sc7mfbv4z3qwutblp2flycdui3baffytbq", addr.String())
}

func TestFilecoinSigner_Sign(t *testing.T) {
	privateKey := privateKeyFromHex(t, "1d969865e189957b9824bd34f26d5cbf357fda1a6d844cbf0c9ab1ed93fa7dbe")
	publicKey, err := sigs.ToPublic(crypto.SigTypeSecp256k1, privateKey)
	require.NoError(t, err)
	fromAddress, err := address.NewSecp256k1Address(publicKey)
	require.NoError(t, err)
	toAddress, err := address.NewFromString("t1rletqqhinhagw6nxjcr4kbfws25thgt7owzuruy")
	require.NoError(t, err)

	tx := types.Message{
		Version:    0,
		To:         toAddress,
		From:       fromAddress,
		Nonce:      1,
		Value:      abi.NewTokenAmount(6000),
		GasLimit:   23423423423423,
		GasFeeCap:  abi.NewTokenAmount(456456456456445645),
		GasPremium: abi.NewTokenAmount(5675674564734345),
		Method:     0,
		Params:     nil,
	}

	sig, err := sigs.Sign(crypto.SigTypeSecp256k1, privateKey, tx.Cid().Bytes())
	require.NoError(t, err)
	signed := types.SignedMessage{
		Message:   tx,
		Signature: *sig,
	}
	sigBuf, err := signed.Serialize()
	require.NoError(t, err)

	require.Equal(t,
		"828a0055018ac93840e869c06b79b748a3c504b696bb339a7f5501cf01bf485f61435e6770b52615bf45"+
			"5e043a236101430017701b0000154db0d523bf49000655a8ba8e851ecd48001429fef64aad8900405842"+
			"01dc6394a67d968b07b6d105cb0bc8b1c76dd688a0f0ad591fc588b70a0cd9e630552994f859439936e6"+
			"61a54164cb43ea19a33bbc4ac43a2fffcaa0464884105000",
		hex.EncodeToString(sigBuf))
}

func TestFilecoinTransaction_Serialize(t *testing.T) {
	privateKey := privateKeyFromHex(t, "2f0f1d2c8de955c7c3fb4d9cae02539fadcb13fa998ccd9a1e871bed95f1941e")
	publicKey, err := sigs.ToPublic(crypto.SigTypeSecp256k1, privateKey)
	require.NoError(t, err)
	fromAddress, err := address.NewSecp256k1Address(publicKey)
	require.NoError(t, err)
	toAddress, err := address.NewFromString("t1hvadvq4rd2pyayrigjx2nbqz2nvemqouslw4wxi")
	require.NoError(t, err)

	tx := types.Message{
		Version:    0,
		To:         toAddress,
		From:       fromAddress,
		Nonce:      0x1234567890,
		Value:      abi.NewTokenAmount(1000),
		GasLimit:   3333333333,
		GasFeeCap:  abi.NewTokenAmount(11111111),
		GasPremium: abi.NewTokenAmount(333333),
		Method:     0,
		Params:     nil,
	}

	sigBuf, err := tx.Serialize()
	require.NoError(t, err)

	require.Equal(t,
		"8a0055013d403ac3911e9f806228326fa68619d36a4641d455013d413d4c3fe3d89f99495a48c6046224"+
			"a71f0cd71b0000001234567890430003e81ac6aea1554400a98ac744000516150040",
		hex.EncodeToString(sigBuf), "Encoded")
	require.Equal(t,
		"0171a0e40220a3b06c2837a94e3a431a78b00536d0298455ceec3d304adf26a3868147c4e6e1",
		hex.EncodeToString(tx.Cid().Bytes()), "CID")
}

func TestEncodeBigInt(t *testing.T) {
	run := func(amount abi.TokenAmount, hexStr string) {
		t.Run(hexStr, func(t *testing.T) {
			buf, err := amount.Bytes()
			require.NoError(t, err)
			assert.Equal(t, hexStr, hex.EncodeToString(buf))
		})
	}
	run(abi.NewTokenAmount(0), "")
	run(abi.NewTokenAmount(1), "0001")
	run(abi.NewTokenAmount(16), "0010")
	run(abi.NewTokenAmount(1111111111111), "000102b36211c7")
	reallyBig := abi.NewTokenAmount(0)
	reallyBig.Lsh(big.NewInt(1), 128)
	run(reallyBig, "000100000000000000000000000000000000")
}

func TestAnySignerFilecoin_Sign(t *testing.T) {
	privateKey := privateKeyFromHex(t, "1d969865e189957b9824bd34f26d5cbf357fda1a6d844cbf0c9ab1ed93fa7dbe")
	publicKey, err := sigs.ToPublic(crypto.SigTypeSecp256k1, privateKey)
	require.NoError(t, err)
	fromAddress, err := address.NewSecp256k1Address(publicKey)
	require.NoError(t, err)
	toAddress, err := address.NewFromString("t3um6uo3qt5of54xjbx3hsxbw5mbsc6auxzrvfxekn5bv3duewqyn2tg5rhrlx73qahzzpkhuj7a34iq7oifsq")
	require.NoError(t, err)

	tx := types.Message{
		Version:    0,
		To:         toAddress,
		From:       fromAddress,
		Nonce:      2,
		Value:      abi.NewTokenAmount(600),
		GasLimit:   1000,
		GasFeeCap:  abi.NewTokenAmount(700),
		GasPremium: abi.NewTokenAmount(800),
		Method:     0,
		Params:     nil,
	}
	tx.Value.Mul(tx.Value.Int, big.NewInt(1_000_000_000))
	tx.Value.Mul(tx.Value.Int, big.NewInt(1_000_000_000))
	t.Log("tx.Value", hex.EncodeToString(tx.Value.Int.Bytes()))
	tx.GasFeeCap.Mul(tx.GasFeeCap.Int, big.NewInt(1_000_000_000))
	tx.GasFeeCap.Mul(tx.GasFeeCap.Int, big.NewInt(1_000_000_000))
	t.Log("tx.GasFeeCap", hex.EncodeToString(tx.GasFeeCap.Int.Bytes()))
	tx.GasPremium.Mul(tx.GasPremium.Int, big.NewInt(1_000_000_000))
	tx.GasPremium.Mul(tx.GasPremium.Int, big.NewInt(1_000_000_000))
	t.Log("tx.GasPremium", hex.EncodeToString(tx.GasPremium.Int.Bytes()))

	sig, err := sigs.Sign(crypto.SigTypeSecp256k1, privateKey, tx.Cid().Bytes())
	require.NoError(t, err)
	signed := types.SignedMessage{
		Message:   tx,
		Signature: *sig,
	}
	sigBuf, err := signed.Serialize()
	require.NoError(t, err)

	require.Equal(t,
		"828a00583103a33d476e13eb8bde5d21becf2b86dd60642f0297cc6a5b914de86bb1d096861ba99bb13c"+
			"577fee003e72f51e89f837c45501cf01bf485f61435e6770b52615bf455e043a2361024a002086ac3510"+
			"526000001903e84a0025f273933db57000004a002b5e3af16b1880000000405842018cc46ef8e67f95fa"+
			"69826a927c6b27b45ad12d6667520dd96262534d12ec56de15d77d74bd1dd5286269684e92e2c36f0ce1"+
			"3ab0482637d6267d390f54adaa3201",
		hex.EncodeToString(sigBuf))
}
