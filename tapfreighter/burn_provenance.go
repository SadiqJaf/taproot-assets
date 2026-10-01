package tapfreighter

import (
	"bytes"
	"context"
	"fmt"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightningnetwork/lnd/chainntnfs"
)

// inputProofFetcher fetches the full proof file of an asset input.
type inputProofFetcher func(ctx context.Context,
	input asset.PrevID) (*proof.File, error)

// buildBurnLeafProof creates the proof that is stored in a supply commitment
// burn leaf. The bare proof suffix of a burn output only describes the burn's
// state transition, it carries no provenance for the inputs that transition
// consumes. A verifier that has no prior snapshot of the input (such as a
// universe server verifying a supply commitment) can therefore not validate
// the witness of the burn and fails with "missing asset input(s)".
//
// To make the leaf self-contained, we return a copy of the suffix that is
// updated with the confirmation data of the anchor transaction and that embeds
// the full proof file of every input the burn output spends as an additional
// input. The passed suffix is not modified.
func buildBurnLeafProof(ctx context.Context, fetchInput inputProofFetcher,
	vPkt *tappsbt.VPacket, vOut *tappsbt.VOutput,
	conf *chainntnfs.TxConfirmation) (*proof.Proof, error) {

	if vOut.ProofSuffix == nil {
		return nil, fmt.Errorf("burn output proof suffix is nil")
	}
	if vOut.Asset == nil {
		return nil, fmt.Errorf("burn output asset is nil")
	}
	if conf == nil {
		return nil, fmt.Errorf("missing confirmation event")
	}

	// Work on a deep copy, the suffix is shared with the virtual packet.
	var buf bytes.Buffer
	if err := vOut.ProofSuffix.Encode(&buf); err != nil {
		return nil, fmt.Errorf("unable to encode burn proof "+
			"suffix: %w", err)
	}
	burnProof := &proof.Proof{}
	if err := burnProof.Decode(bytes.NewReader(buf.Bytes())); err != nil {
		return nil, fmt.Errorf("unable to decode burn proof "+
			"suffix: %w", err)
	}

	// The suffix was created before the anchor transaction confirmed, so
	// it needs the block header, height and merkle proof.
	err := burnProof.UpdateTransitionProof(&proof.BaseProofParams{
		Block:       conf.Block,
		BlockHeight: conf.BlockHeight,
		Tx:          conf.Tx,
		TxIndex:     int(conf.TxIndex),
	})
	if err != nil {
		return nil, fmt.Errorf("unable to update burn proof: %w", err)
	}

	// Find the inputs that the burn output's witnesses spend. For a split
	// burn the witnesses of the split root are the relevant ones.
	witnessPrevIDs := make(map[asset.PrevID]struct{})
	for _, witness := range vOut.Asset.Witnesses() {
		if witness.PrevID != nil {
			witnessPrevIDs[*witness.PrevID] = struct{}{}
		}
	}

	var inputs []asset.PrevID
	for _, in := range vPkt.Inputs {
		if _, ok := witnessPrevIDs[in.PrevID]; ok {
			inputs = append(inputs, in.PrevID)
		}
	}
	if len(inputs) == 0 {
		return nil, fmt.Errorf("no inputs matched the witnesses of " +
			"the burn output")
	}

	// Embed the complete provenance of every input.
	burnProof.AdditionalInputs = nil
	for _, input := range inputs {
		inputFile, err := fetchInput(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch proof of "+
				"burn input %v: %w", input.OutPoint, err)
		}

		burnProof.AdditionalInputs = append(
			burnProof.AdditionalInputs, *inputFile,
		)
	}

	return burnProof, nil
}
