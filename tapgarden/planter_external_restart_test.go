package tapgarden_test

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/stretchr/testify/require"
)

// panicGenesisSigner makes an accidental startup/seal signer invocation
// unmistakable. An externally witnessed pending batch must be recoverable
// without touching the local signer.
type panicGenesisSigner struct{}

func (panicGenesisSigner) SignVirtualTx(*lndclient.SignDescriptor,
	*wire.MsgTx, *wire.TxOut) (*schnorr.Signature, error) {
	panic("local genesis signer invoked while recovering external V0 batch")
}

func newExternalRestartPlanter(h *mintingTestHarness,
	signer asset.GenesisSigner) *tapgarden.ChainPlanter {
	return tapgarden.NewChainPlanter(tapgarden.PlanterConfig{
		GardenKit: tapgarden.GardenKit{
			Wallet:       h.wallet,
			ChainBridge:  h.chain,
			Log:          h.store,
			TreeStore:    h.treeStore,
			KeyRing:      h.keyRing,
			GenSigner:    signer,
			GenTxBuilder: h.genTxBuilder,
			TxValidator:  h.txValidator,
			ProofFiles:   h.proofFiles,
			ProofWatcher: h.proofWatcher,
		},
		ChainParams:  *chainParams,
		ProofUpdates: h.proofFiles,
		ErrChan:      h.errChan,
	})
}

func TestExternalV0OriginAndLaterBatchSurviveRestart(t *testing.T) {
	store := newMintingStore(t)
	h := newMintingTestHarness(t, store)
	h.refreshChainPlanter()

	// Use a raw key with the zero locator/family to model a non-LND owner.
	// The later tranche is anchored to this origin in the same funded batch.
	externalGroupKey, _ := test.RandKeyDesc(t)
	externalGroupKey.Family = 0
	origin := &tapgarden.Seedling{
		AssetType:         asset.Normal,
		AssetName:         "external-origin",
		Amount:            100,
		Meta:              &proof.MetaReveal{},
		EnableEmission:    true,
		SupplyCommitments: true,
		GroupInternalKey:  &externalGroupKey,
	}
	later := &tapgarden.Seedling{
		AssetType:         asset.Normal,
		AssetName:         "external-later",
		Amount:            25,
		Meta:              &proof.MetaReveal{},
		SupplyCommitments: true,
		GroupAnchor:       &origin.AssetName,
	}

	h.queueSeedlingsInBatch(false, origin, later)

	var (
		wg       sync.WaitGroup
		respChan = make(chan *FundBatchResp, 1)
	)
	h.fundBatch(&wg, respChan, nil)
	h.assertGenesisTxFunded(nil)
	funded := h.assertFundBatch(&wg, respChan, "")
	require.NotNil(t, funded)
	require.True(t, funded.IsFunded())

	var originalPSBT bytes.Buffer
	require.NoError(t, funded.GenesisPacket.Pkt.Serialize(&originalPSBT))
	originalBatchKey := funded.BatchKey.PubKey.SerializeCompressed()

	require.NoError(t, h.planter.Stop())
	h.planter = newExternalRestartPlanter(h, panicGenesisSigner{})
	require.NoError(t, h.planter.Start())

	pending, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.NotNil(t, pending)
	require.Equal(t, originalBatchKey,
		pending.BatchKey.PubKey.SerializeCompressed())
	require.Len(t, pending.Seedlings, 2)
	require.True(t, pending.IsFunded())

	var recoveredPSBT bytes.Buffer
	require.NoError(t, pending.GenesisPacket.Pkt.Serialize(&recoveredPSBT))
	require.Equal(t, originalPSBT.Bytes(), recoveredPSBT.Bytes())

	require.Equal(t, 0, mustNumActiveBatches(t, h.planter))
	allBatches, err := store.FetchAllBatches(context.Background())
	require.NoError(t, err)
	require.Len(t, allBatches, 1)
	require.Equal(t, tapgarden.BatchStatePending, allBatches[0].State())

	// The recovered funded batch remains immutable. The error is delivered on
	// the seedling update channel because QueueNewSeedling itself is async.
	updates, err := h.planter.QueueNewSeedling(&tapgarden.Seedling{})
	require.NoError(t, err)
	update, err := fn.RecvOrTimeout(updates, defaultTimeout)
	require.NoError(t, err)
	require.ErrorIs(t, update.Error, tapgarden.ErrBatchAlreadyFunded)

	postAttempt, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.Equal(t, originalBatchKey,
		postAttempt.BatchKey.PubKey.SerializeCompressed())
	require.Len(t, postAttempt.Seedlings, 2)
	require.True(t, postAttempt.IsFunded())

	require.NoError(t, h.planter.Stop())
}

func mustNumActiveBatches(t *testing.T, planter *tapgarden.ChainPlanter) int {
	t.Helper()
	n, err := planter.NumActiveBatches()
	require.NoError(t, err)
	return n
}

var _ asset.GenesisSigner = panicGenesisSigner{}
