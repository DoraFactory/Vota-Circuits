pragma circom 2.0.0;

include "../../../circuits/amaci/power/processDeactivate.circom";

// state_tree_depth,
// batch_size

component main {
  public [
    inputHash
  ]
} = ProcessDeactivateMessages(4, 25);
