pragma circom 2.0.0;

include "../../../../../../circuits/maci/power/tallyVotes.circom";

// state_tree_depth,
// int_state_tree_depth,
// vote_options_tree_depth

component main {
  public [
    inputHash
  ]
} = TallyVotes(9, 4, 3);
