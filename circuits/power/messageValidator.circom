pragma circom 2.0.0;

include "./verifySignature.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

template MessageValidator() {
    // a) Whether the state leaf index is valid
    signal input stateTreeIndex;
    signal input numSignUps;
    component validStateLeafIndex = LessEqThan(252);
    validStateLeafIndex.in[0] <== stateTreeIndex;
    validStateLeafIndex.in[1] <== numSignUps;

    // b) Whether the max vote option tree index is correct
    signal input voteOptionIndex;
    signal input maxVoteOptions;
    component validVoteOptionIndex = LessThan(252);
    validVoteOptionIndex.in[0] <== voteOptionIndex;
    validVoteOptionIndex.in[1] <== maxVoteOptions;

    // c) Whether the nonce is correct
    signal input originalNonce;
    signal input nonce;
    component validNonce = IsEqual();
    validNonce.in[0] <== originalNonce + 1;
    validNonce.in[1] <== nonce;

    var PACKED_CMD_LENGTH = 3;
    // d) Whether the signature is correct
    signal input cmd[PACKED_CMD_LENGTH];
    signal input pubKey[2];
    signal input sigR8[2];
    signal input sigS;

    component validSignature = VerifySignature();
    validSignature.pubKey[0] <== pubKey[0];
    validSignature.pubKey[1] <== pubKey[1];
    validSignature.R8[0] <== sigR8[0];
    validSignature.R8[1] <== sigR8[1];
    validSignature.S <== sigS;
    for (var i = 0; i < PACKED_CMD_LENGTH; i ++) {
        validSignature.preimage[i] <== cmd[i];
    }

    // e) Whether the state leaf was inserted before the Poll period ended
    // signal input slTimestamp;
    // signal input pollEndTimestamp;
    // component validTimestamp = LessEqThan(252);
    // validTimestamp.in[0] <== slTimestamp;
    // validTimestamp.in[1] <== pollEndTimestamp;

    // e) Using quadratic deduction or linear deduction
    signal input isQuadraticCost;

    // f) Whether there are sufficient voice credits
    signal input currentVoiceCreditBalance;
    signal input currentVotesForOption;
    signal input voteWeight;

    signal output newBalance;

    // Check that voteWeight is < sqrt(field size), so voteWeight ^ 2 will not
    // overflow
    component validVoteWeight = LessEqThan(252);
    validVoteWeight.in[0] <== voteWeight;
    validVoteWeight.in[1] <== 147946756881789319005730692170996259609;

    // Check that currentVoiceCreditBalance + currentCostsForOption >= cost
    component currentCostsForOption = Mux1();
    currentCostsForOption.s <== isQuadraticCost;
    currentCostsForOption.c[0] <== currentVotesForOption;
    currentCostsForOption.c[1] <== currentVotesForOption * currentVotesForOption;

    component cost = Mux1();
    cost.s <== isQuadraticCost;
    cost.c[0] <== voteWeight;
    cost.c[1] <== voteWeight * voteWeight;

    component sufficientVoiceCredits = GreaterEqThan(252);
    sufficientVoiceCredits.in[0] <== currentCostsForOption.out + currentVoiceCreditBalance;
    sufficientVoiceCredits.in[1] <== cost.out;

    newBalance <== currentVoiceCreditBalance + currentCostsForOption.out - cost.out;

    component validUpdate = IsEqual();
    validUpdate.in[0] <== 6;
    validUpdate.in[1] <== validSignature.valid + 
                          sufficientVoiceCredits.out +
                          validVoteWeight.out +
                          validNonce.out +
                          validStateLeafIndex.out +
                        //   validTimestamp.out +
                          validVoteOptionIndex.out;
    signal output isValid;
    isValid <== validUpdate.out;

    // For debugging
    /*signal output isValidSignature;*/
    /*signal output isValidVc;*/
    /*signal output isValidNonce;*/
    /*signal output isValidSli;*/
    /*signal output isValidVoi;*/

    /*isValidSignature <== validSignature.valid;*/
    /*isValidVc <== sufficientVoiceCredits.out;*/
    /*isValidNonce <== validNonce.out;*/
    /*isValidSli <== validStateLeafIndex.out;*/
    /*isValidVoi <== validVoteOptionIndex.out;*/
}
