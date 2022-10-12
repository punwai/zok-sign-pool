# zok-sign-pool

1. `python3 script.py`
This will generate the witnesses to generate a proof for. It creates a random set of validators (defaulted to 5 total validators), gets N (defaulted to 3) of them to sign, and generates a merkle root for the validator public key set.

2. `sh compile.sh`
Compile the circuit

3. `sh witness.sh`
Generate generate a proof for the witnesses we generated in step 1.