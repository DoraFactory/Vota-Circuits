pragma circom 2.0.0;

include "../../../circuits/amaci/power/tallyVotes.circom";

// state_tree_depth,
// int_state_tree_depth,
// vote_options_tree_depth

component main {
  public [
    inputHash
  ]
} = TallyVotes(2, 1, 1);
