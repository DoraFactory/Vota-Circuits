pragma circom 2.0.0;

include "../../circuits/power/processMessages.circom";

// state_tree_depth,
// vote_options_tree_depth,
// batch_size

component main {
  public [
    inputHash
  ]
} = ProcessMessages(9, 3, 625);
