package rpcserver

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// testPacket returns a PSBT with the given number of (empty) outputs.
func testPacket(t *testing.T, numOutputs int) *psbt.Packet {
	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	for i := 0; i < numOutputs; i++ {
		tx.AddTxOut(&wire.TxOut{Value: 1000})
	}

	pkt, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	return pkt
}

func clonePacket(t *testing.T, pkt *psbt.Packet) *psbt.Packet {
	t.Helper()

	raw, err := pkt.B64Encode()
	require.NoError(t, err)

	clone, err := psbt.NewFromRawBytes(bytes.NewReader([]byte(raw)), true)
	require.NoError(t, err)

	return clone
}

// TestCheckNoNewAnchorChange makes sure the add=false guard for
// CommitVirtualPsbts (taproot-assets#2209) fails closed whenever lnd changed
// the output set of the anchor template and only passes if it is untouched.
func TestCheckNoNewAnchorChange(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		template    int
		funded      int
		changeIndex int32
		alterOut    int
		expectErr   bool
	}{{
		name:        "unchanged outputs, no change index",
		template:    2,
		funded:      2,
		changeIndex: -1,
		alterOut:    -1,
	}, {
		name:        "change output appended",
		template:    2,
		funded:      3,
		changeIndex: 2,
		alterOut:    -1,
		expectErr:   true,
	}, {
		name:        "change index reported without new output",
		template:    2,
		funded:      2,
		changeIndex: 1,
		alterOut:    -1,
		expectErr:   true,
	}, {
		name:        "output appended without change index",
		template:    1,
		funded:      2,
		changeIndex: -1,
		alterOut:    -1,
		expectErr:   true,
	}, {
		name:        "output removed",
		template:    2,
		funded:      1,
		changeIndex: -1,
		alterOut:    -1,
		expectErr:   true,
	}, {
		name:        "template output value altered in place",
		template:    2,
		funded:      2,
		changeIndex: -1,
		alterOut:    1,
		expectErr:   true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			template := testPacket(t, tc.template)
			var funded *psbt.Packet
			switch {
			case tc.funded == tc.template && tc.alterOut < 0:
				funded = template
			case tc.alterOut >= 0:
				funded = clonePacket(t, template)
				funded.UnsignedTx.TxOut[tc.alterOut].Value = 999
			default:
				funded = testPacket(t, tc.funded)
				for idx := 0; idx < tc.template && idx < tc.funded; idx++ {
					funded.UnsignedTx.TxOut[idx] =
						template.UnsignedTx.TxOut[idx]
				}
			}

			err := checkNoNewAnchorChange(
				template, funded, tc.changeIndex,
			)
			if !tc.expectErr {
				require.NoError(t, err)
				return
			}

			require.ErrorIs(t, err, ErrAnchorChangeAdded)
			require.ErrorContains(t, err, "#2209")
		})
	}
}
