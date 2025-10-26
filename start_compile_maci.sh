#!/bin/sh

# Check if parameter is provided
if [ -z "$1" ]; then
  echo "Input the circuit power, like 2-1-1-5/4-2-2-25"
  exit 1
fi

# Use provided parameter as output directory
OUTPUT_DIR="build/maci/$1"

compile_and_ts_and_witness() {

  mkdir inputs
  npm install

  #compile circuits
  mkdir -p $OUTPUT_DIR/r1cs

  echo $(date +"%T") "compile the circuit into r1cs, wasm and sym"
  itime="$(date -u +%s)"
  circom external/vota-circuits/circuits/maci/power/prod/msg.circom --r1cs --wasm --sym -o $OUTPUT_DIR/r1cs
  circom external/vota-circuits/circuits/maci/power/prod/tally.circom --r1cs --wasm --sym -o $OUTPUT_DIR/r1cs
  ftime="$(date -u +%s)"
  echo "	($(($(date -u +%s)-$itime))s)"

  # create zkey
  echo $(date +"%T") "start create zkey"
  mkdir -p $OUTPUT_DIR/zkey
  snarkjs g16s $OUTPUT_DIR/r1cs/msg.r1cs ptau/powersOfTau28_hez_final_18.ptau $OUTPUT_DIR/zkey/msg_0.zkey
  snarkjs g16s $OUTPUT_DIR/r1cs/tally.r1cs ptau/powersOfTau28_hez_final_18.ptau $OUTPUT_DIR/zkey/tally_0.zkey
  # output verification key
  echo $(date +"%T") "output verification key"
  mkdir -p $OUTPUT_DIR/verification_key/msg
  mkdir -p $OUTPUT_DIR/verification_key/tally

  snarkjs zkc $OUTPUT_DIR/zkey/msg_0.zkey $OUTPUT_DIR/zkey/msg.zkey --name="DoraHacks" -v
  snarkjs zkev $OUTPUT_DIR/zkey/msg.zkey $OUTPUT_DIR/verification_key/msg/verification_key.json
  
  snarkjs zkc $OUTPUT_DIR/zkey/tally_0.zkey $OUTPUT_DIR/zkey/tally.zkey --name="DoraHacks" -v
  snarkjs zkev $OUTPUT_DIR/zkey/tally.zkey $OUTPUT_DIR/verification_key/tally/verification_key.json

  # format vkey
  node js/format_vkey.js $OUTPUT_DIR/verification_key/msg/verification_key.json $OUTPUT_DIR/verification_key/msg/verification_key_hex.json
  node js/format_vkey.js $OUTPUT_DIR/verification_key/tally/verification_key.json $OUTPUT_DIR/verification_key/tally/verification_key_hex.json

  echo "everything is ok"
}

echo "compile & trustesetup for maci circuit(msg, tally)"
compile_and_ts_and_witness