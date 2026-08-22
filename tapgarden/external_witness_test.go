package tapgarden

import (
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

func testExternalKeyDescriptor(t *testing.T, family keychain.KeyFamily) keychain.KeyDescriptor {
	t.Helper()
	_, pub := btcec.PrivKeyFromBytes(bytesForTestKey())
	return keychain.KeyDescriptor{
		KeyLocator: keychain.KeyLocator{Family: family, Index: 7},
		PubKey:     pub,
	}
}

func bytesForTestKey() []byte {
	return []byte{1}
}

func TestValidateGroupKeyExternalV0Only(t *testing.T) {
	require.Error(t, (Seedling{}).validateGroupKey(asset.AssetGroup{}, nil))

	desc := testExternalKeyDescriptor(t, 0)
	groupKey := &asset.GroupKey{
		Version:     asset.GroupKeyV0,
		RawKey:      desc,
		GroupPubKey: *desc.PubKey,
	}
	group := asset.AssetGroup{
		Genesis:  &asset.Genesis{Type: asset.Normal},
		GroupKey: groupKey,
	}
	seedling := Seedling{
		AssetType:         asset.Normal,
		SupplyCommitments: true,
	}

	require.NoError(t, seedling.validateGroupKey(group, nil))

	groupKey.Version = asset.GroupKeyV1
	require.Error(t, seedling.validateGroupKey(group, nil))
}

func TestBatchRequiresExternalV0Witness(t *testing.T) {
	desc := testExternalKeyDescriptor(t, 0)
	batch := &MintingBatch{
		Seedlings: map[string]*Seedling{
			"later": {
				SupplyCommitments: true,
				GroupInfo: &asset.AssetGroup{GroupKey: &asset.GroupKey{
					Version: asset.GroupKeyV0, RawKey: desc,
				}},
			},
		},
	}

	require.True(t, batchRequiresExternalV0Witness(batch))
	desc.Family = asset.TaprootAssetsKeyFamily
	batch.Seedlings["later"].GroupInfo.GroupKey.RawKey = desc
	require.False(t, batchRequiresExternalV0Witness(batch))
	desc.Family = 0
	require.True(t, batchRequiresExternalV0Witness(&MintingBatch{
		Seedlings: map[string]*Seedling{"origin": {
			EnableEmission: true, SupplyCommitments: true,
			GroupInternalKey: &desc,
		}},
	}))
}

func TestCollectExternalWitnessesRejectsInvalidUnions(t *testing.T) {
	knownID := asset.ID{1}
	unknownID := asset.ID{2}
	known := func(id asset.ID) bool {
		return id == knownID
	}
	witness := PendingGroupWitness{
		GenID:   knownID,
		Witness: wire.TxWitness{make([]byte, 64)},
	}

	got, err := collectExternalWitnesses(
		[]PendingGroupWitness{witness}, known,
	)
	require.NoError(t, err)
	require.Len(t, got, 1)

	_, err = collectExternalWitnesses(
		[]PendingGroupWitness{witness, witness}, known,
	)
	require.Error(t, err)

	witness.GenID = unknownID
	_, err = collectExternalWitnesses(
		[]PendingGroupWitness{witness}, known,
	)
	require.Error(t, err)
}

func TestValidExternalV0WitnessStack(t *testing.T) {
	tests := []struct {
		name  string
		stack wire.TxWitness
		want  bool
	}{
		{name: "empty", stack: wire.TxWitness{}},
		{name: "short", stack: wire.TxWitness{make([]byte, 63)}},
		{name: "valid", stack: wire.TxWitness{make([]byte, 64)}, want: true},
		{name: "long", stack: wire.TxWitness{make([]byte, 65)}},
		{name: "extra", stack: wire.TxWitness{make([]byte, 64), make([]byte, 1)}},
		{name: "annex", stack: wire.TxWitness{make([]byte, 64), []byte{0x50}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, validExternalV0WitnessStack(test.stack))
		})
	}
}

func TestRequireExternalV0Witnesses(t *testing.T) {
	desc := testExternalKeyDescriptor(t, 0)
	assetV0 := &asset.Asset{Genesis: asset.Genesis{Tag: "v0"}}
	assetLocal := &asset.Asset{Genesis: asset.Genesis{Tag: "local"}}
	reqV0 := asset.GroupKeyRequest{
		Version: asset.GroupKeyV0, RawKey: desc, NewAsset: assetV0,
	}
	reqLocal := asset.GroupKeyRequest{
		Version: asset.GroupKeyV0,
		RawKey: keychain.KeyDescriptor{
			KeyLocator: keychain.KeyLocator{
				Family: asset.TaprootAssetsKeyFamily,
			},
			PubKey: desc.PubKey,
		},
		NewAsset: assetLocal,
	}
	reqScriptPath := reqV0
	reqScriptPath.TapscriptRoot = []byte{1}

	required := map[asset.ID]struct{}{assetV0.ID(): {}}
	err := requireExternalV0Witnesses(required, nil)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrExternalGroupWitnessRequired))

	require.NoError(t, requireExternalV0Witnesses(
		required,
		map[asset.ID]PendingGroupWitness{
			assetV0.ID(): {GenID: assetV0.ID()},
		},
	))
	require.NoError(t, requireExternalV0Witnesses(nil, nil))
	require.True(t, groupKeyRequestIsLocal(reqLocal))
	require.False(t, externalV0GroupKeyRequest(reqScriptPath))
}

func TestRequiredExternalV0WitnessIDsOnlyKnownGroups(t *testing.T) {
	desc := testExternalKeyDescriptor(t, 0)
	originAsset := &asset.Asset{Genesis: asset.Genesis{Tag: "origin"}}
	laterAsset := &asset.Asset{Genesis: asset.Genesis{Tag: "later"}}
	reqs := []asset.GroupKeyRequest{
		{Version: asset.GroupKeyV0, RawKey: desc, NewAsset: originAsset},
		{Version: asset.GroupKeyV0, RawKey: desc, NewAsset: laterAsset},
	}
	seedlings := map[string]*Seedling{
		"origin": {
			EnableEmission: true, SupplyCommitments: true,
			GroupInternalKey: &desc,
		},
		"later": {
			SupplyCommitments: true,
			GroupInfo: &asset.AssetGroup{GroupKey: &asset.GroupKey{
				Version: asset.GroupKeyV0, RawKey: desc,
			}},
		},
	}

	required := requiredExternalV0WitnessIDs(reqs, seedlings)
	require.Contains(t, required, originAsset.ID())
	require.Contains(t, required, laterAsset.ID())
}

func TestBatchRequiresExternalV0WitnessConditions(t *testing.T) {
	nonLocal := testExternalKeyDescriptor(t, 0)
	local := testExternalKeyDescriptor(t, asset.TaprootAssetsKeyFamily)

	newBatch := func(seedling *Seedling) *MintingBatch {
		return &MintingBatch{Seedlings: map[string]*Seedling{"asset": seedling}}
	}
	groupSeedling := func(desc keychain.KeyDescriptor,
		version asset.GroupKeyVersion, root []byte, supply bool) *Seedling {
		return &Seedling{
			SupplyCommitments: supply,
			GroupInfo: &asset.AssetGroup{GroupKey: &asset.GroupKey{
				Version: version, RawKey: desc, TapscriptRoot: root,
			}},
		}
	}

	require.True(t, batchRequiresExternalV0Witness(newBatch(&Seedling{
		EnableEmission: true, SupplyCommitments: true,
		GroupInternalKey: &nonLocal,
	})))
	require.True(t, batchRequiresExternalV0Witness(newBatch(
		groupSeedling(nonLocal, asset.GroupKeyV0, nil, true),
	)))
	require.False(t, batchRequiresExternalV0Witness(newBatch(
		groupSeedling(nonLocal, asset.GroupKeyV0, nil, false),
	)))
	require.False(t, batchRequiresExternalV0Witness(newBatch(
		groupSeedling(nonLocal, asset.GroupKeyV1, nil, true),
	)))
	require.False(t, batchRequiresExternalV0Witness(newBatch(
		groupSeedling(nonLocal, asset.GroupKeyV0, []byte{1}, true),
	)))
	require.False(t, batchRequiresExternalV0Witness(newBatch(
		groupSeedling(local, asset.GroupKeyV0, nil, true),
	)))
}

func TestFundedBatchImmutabilityIsExternalV0Scoped(t *testing.T) {
	nonLocal := testExternalKeyDescriptor(t, 0)
	local := testExternalKeyDescriptor(t, asset.TaprootAssetsKeyFamily)

	externalBatch := &MintingBatch{
		GenesisPacket: &FundedMintAnchorPsbt{},
		Seedlings: map[string]*Seedling{"external": {
			SupplyCommitments: true,
			GroupInfo: &asset.AssetGroup{GroupKey: &asset.GroupKey{
				Version: asset.GroupKeyV0, RawKey: nonLocal,
			}},
		}},
	}
	localBatch := &MintingBatch{
		GenesisPacket: &FundedMintAnchorPsbt{},
		Seedlings: map[string]*Seedling{"local": {
			EnableEmission: true, SupplyCommitments: true,
			GroupInternalKey: &local,
		}},
	}

	require.True(t, externalBatch.IsFunded())
	require.True(t, batchRequiresExternalV0Witness(externalBatch))
	require.True(t, localBatch.IsFunded())
	require.False(t, batchRequiresExternalV0Witness(localBatch))
}

func TestPrepAssetSeedlingRejectsFundedBatch(t *testing.T) {
	nonLocal := testExternalKeyDescriptor(t, 0)
	planter := &ChainPlanter{
		pendingBatch: &MintingBatch{
			GenesisPacket: &FundedMintAnchorPsbt{},
			Seedlings: map[string]*Seedling{"external": {
				SupplyCommitments: true,
				GroupInfo: &asset.AssetGroup{GroupKey: &asset.GroupKey{
					Version: asset.GroupKeyV0, RawKey: nonLocal,
				}},
			}},
		},
	}

	err := planter.prepAssetSeedling(context.Background(), &Seedling{})
	require.ErrorIs(t, err, ErrBatchAlreadyFunded)
}
