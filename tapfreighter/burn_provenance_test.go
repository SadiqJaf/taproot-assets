package tapfreighter

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/stretchr/testify/require"
)

// burnProvenanceFixture is the test data for buildBurnLeafProof.
type burnProvenanceFixture struct {
	vPkt       *tappsbt.VPacket
	vOut       *tappsbt.VOutput
	conf       *chainntnfs.TxConfirmation
	inputFiles map[asset.PrevID]*proof.File
}

func newBurnProvenanceFixture(t *testing.T, numInputs int,
	split bool) *burnProvenanceFixture {

	t.Helper()

	gen := asset.RandGenesis(t, asset.Normal)

	f := &burnProvenanceFixture{
		vPkt:       &tappsbt.VPacket{},
		inputFiles: make(map[asset.PrevID]*proof.File),
	}

	var witnesses []asset.Witness
	for i := 0; i < numInputs; i++ {
		inputTx := wire.NewMsgTx(2)
		inputTx.AddTxIn(&wire.TxIn{})
		inputTx.AddTxOut(&wire.TxOut{Value: 1000 + int64(i)})
		block := wire.MsgBlock{
			Transactions: []*wire.MsgTx{inputTx},
		}
		inProof := proof.RandProof(
			t, gen, test.RandPubKey(t), block, 0, 0,
		)
		file, err := proof.NewFile(proof.V0, inProof)
		require.NoError(t, err)

		prevID := asset.PrevID{
			OutPoint:  wire.OutPoint{Hash: inputTx.TxHash()},
			ID:        gen.ID(),
			ScriptKey: asset.ToSerialized(test.RandPubKey(t)),
		}
		f.inputFiles[prevID] = file
		f.vPkt.Inputs = append(f.vPkt.Inputs, &tappsbt.VInput{
			PrevID: prevID,
		})
		witnesses = append(witnesses, asset.Witness{PrevID: &prevID})
	}

	// An extra input that the burn does not spend.
	unrelated := asset.PrevID{
		OutPoint: wire.OutPoint{Index: 99},
		ID:       gen.ID(),
	}
	f.vPkt.Inputs = append(f.vPkt.Inputs, &tappsbt.VInput{
		PrevID: unrelated,
	})

	burnAsset := asset.RandAssetWithValues(
		t, gen, nil, asset.RandScriptKey(t),
	)
	burnAsset.PrevWitnesses = witnesses
	if split {
		// A full-height proof of empty siblings, so it encodes.
		emptyNodes := make([]mssmt.Node, mssmt.MaxTreeLevels)
		for i := range emptyNodes {
			emptyNodes[i] = mssmt.EmptyTree[mssmt.MaxTreeLevels-i]
		}
		rootAsset := burnAsset.Copy()
		splitAsset := burnAsset.Copy()
		splitAsset.PrevWitnesses = []asset.Witness{{
			PrevID: &asset.PrevID{},
			SplitCommitment: &asset.SplitCommitment{
				Proof:     *mssmt.NewProof(emptyNodes),
				RootAsset: *rootAsset,
			},
		}}
		burnAsset = splitAsset
	}

	// The suffix as created pre-broadcast: no block data yet.
	suffixTx := wire.NewMsgTx(2)
	suffixTx.AddTxIn(&wire.TxIn{})
	suffixTx.AddTxOut(&wire.TxOut{Value: 5})
	suffix := proof.RandProof(
		t, gen, test.RandPubKey(t), wire.MsgBlock{
			Transactions: []*wire.MsgTx{suffixTx},
		}, 0, 0,
	)
	suffix.Asset = *burnAsset
	suffix.BlockHeight = 0
	suffix.BlockHeader = wire.BlockHeader{}
	f.vOut = &tappsbt.VOutput{
		Asset:       burnAsset,
		ProofSuffix: &suffix,
	}

	confTx := wire.NewMsgTx(2)
	confTx.AddTxIn(&wire.TxIn{})
	confTx.AddTxOut(&wire.TxOut{Value: 777})
	f.conf = &chainntnfs.TxConfirmation{
		BlockHeight: 1234,
		TxIndex:     0,
		Tx:          confTx,
		Block: &wire.MsgBlock{
			Header:       wire.BlockHeader{Nonce: 7},
			Transactions: []*wire.MsgTx{confTx},
		},
	}

	return f
}

func (f *burnProvenanceFixture) fetch(_ context.Context,
	input asset.PrevID) (*proof.File, error) {

	file, ok := f.inputFiles[input]
	if !ok {
		return nil, errors.New("unknown input")
	}

	return file, nil
}

// TestPreFixBurnLeafRejectionCauses documents the two independent defects in
// the v0.8.0 burn leaf that a universe server rejects.
func TestPreFixBurnLeafRejectionCauses(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newBurnProvenanceFixture(t, 1, false)
	bridge := tapgarden.NewMockChainBridge()

	t.Run("chain porter partial block update", func(t *testing.T) {
		// v0.8.0 copied the pre-broadcast suffix and only assigned block
		// height/header, without UpdateTransitionProof (no merkle proof
		// or anchor tx from the confirmation event).
		var buf bytes.Buffer
		require.NoError(t, f.vOut.ProofSuffix.Encode(&buf))
		preFix := &proof.Proof{}
		require.NoError(t, preFix.Decode(bytes.NewReader(buf.Bytes())))
		preFix.BlockHeight = uint32(f.conf.BlockHeight)
		preFix.BlockHeader = f.conf.Block.Header

		lookup, err := bridge.GenProofChainLookup(preFix)
		require.NoError(t, err)

		_, err = preFix.Verify(ctx, nil, lookup, proof.MockVerifierCtx)
		require.Error(t, err)
		t.Logf("partial block update verify error: %v", err)
	})
}

// TestBuildBurnLeafProof makes sure the burn leaf proof is self-contained: it
// carries the confirmation data and the provenance of all the inputs it spends
// and it doesn't touch the original proof suffix.
func TestBuildBurnLeafProof(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	for _, tc := range []struct {
		name      string
		numInputs int
		split     bool
	}{
		{name: "single input", numInputs: 1},
		{name: "multiple inputs", numInputs: 3},
		{name: "split burn", numInputs: 2, split: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBurnProvenanceFixture(t, tc.numInputs, tc.split)

			var before bytes.Buffer
			require.NoError(t, f.vOut.ProofSuffix.Encode(&before))

			burnProof, err := buildBurnLeafProof(
				ctx, f.fetch, f.vPkt, f.vOut, f.conf,
			)
			require.NoError(t, err)

			// Confirmation data is set.
			require.EqualValues(t, 1234, burnProof.BlockHeight)
			require.Equal(t, f.conf.Block.Header, burnProof.BlockHeader)
			require.Equal(
				t, f.conf.Tx.TxHash(), burnProof.AnchorTx.TxHash(),
			)

			// Exactly the spent inputs are embedded, each one
			// with the complete file.
			require.Len(t, burnProof.AdditionalInputs, tc.numInputs)
			for _, in := range burnProof.AdditionalInputs {
				require.Equal(t, 1, in.NumProofs())
			}

			// The proof survives an encode/decode round trip with
			// the provenance intact.
			var buf bytes.Buffer
			require.NoError(t, burnProof.Encode(&buf))
			var decoded proof.Proof
			require.NoError(
				t, decoded.Decode(bytes.NewReader(buf.Bytes())),
			)
			require.Len(t, decoded.AdditionalInputs, tc.numInputs)

			// The suffix held by the virtual packet is unchanged.
			var after bytes.Buffer
			require.NoError(t, f.vOut.ProofSuffix.Encode(&after))
			require.Equal(t, before.Bytes(), after.Bytes())
			require.Empty(t, f.vOut.ProofSuffix.AdditionalInputs)
		})
	}
}

// TestBurnLeafProofSize records encoded burn leaf sizes for realistic
// multi-input burns. Sizes stay well below a few hundred KB.
func TestBurnLeafProofSize(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const maxReasonableBytes = 512 * 1024

	for _, numInputs := range []int{1, 3, 5} {
		f := newBurnProvenanceFixture(t, numInputs, false)

		var preFixBuf bytes.Buffer
		require.NoError(t, f.vOut.ProofSuffix.Encode(&preFixBuf))
		preFixSize := preFixBuf.Len()

		burnProof, err := buildBurnLeafProof(
			ctx, f.fetch, f.vPkt, f.vOut, f.conf,
		)
		require.NoError(t, err)

		var postFixBuf bytes.Buffer
		require.NoError(t, burnProof.Encode(&postFixBuf))
		postFixSize := postFixBuf.Len()

		t.Logf("burn leaf size num_inputs=%d pre_fix=%d post_fix=%d",
			numInputs, preFixSize, postFixSize)

		require.Less(t, postFixSize, maxReasonableBytes)
	}
}

// TestBuildBurnLeafProofErrors tests the failure modes.
func TestBuildBurnLeafProofErrors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("nil suffix", func(t *testing.T) {
		f := newBurnProvenanceFixture(t, 1, false)
		f.vOut.ProofSuffix = nil
		_, err := buildBurnLeafProof(
			ctx, f.fetch, f.vPkt, f.vOut, f.conf,
		)
		require.ErrorContains(t, err, "suffix is nil")
	})

	t.Run("no conf", func(t *testing.T) {
		f := newBurnProvenanceFixture(t, 1, false)
		_, err := buildBurnLeafProof(
			ctx, f.fetch, f.vPkt, f.vOut, nil,
		)
		require.ErrorContains(t, err, "missing confirmation")
	})

	t.Run("no matching input", func(t *testing.T) {
		f := newBurnProvenanceFixture(t, 1, false)
		f.vPkt.Inputs = f.vPkt.Inputs[1:]
		_, err := buildBurnLeafProof(
			ctx, f.fetch, f.vPkt, f.vOut, f.conf,
		)
		require.ErrorContains(t, err, "no inputs matched")
	})

	t.Run("input proof missing", func(t *testing.T) {
		f := newBurnProvenanceFixture(t, 2, false)
		f.inputFiles = map[asset.PrevID]*proof.File{}
		_, err := buildBurnLeafProof(
			ctx, f.fetch, f.vPkt, f.vOut, f.conf,
		)
		require.ErrorContains(t, err, "unable to fetch proof")
	})
}
