# Simulating a Vote

A CLI tool that runs a complete end-to-end election using the ElectionGuard v2.1
cryptographic protocol. Generates an election, performs a key ceremony, encrypts
ballots, tallies homomorphically, decrypts with threshold guardians, and verifies
every proof -- all from a single command.

## Usage

```bash
cargo run --release -- [OPTIONS]
```

Always use `--release` -- 4096-bit cryptographic operations are 10-20x faster
with compiler optimizations.

## Options

```
  -n, --guardians <N>       Number of guardians [default: 3]
  -k, --threshold <K>       Decryption threshold, must be <= guardians [default: 2]
  -b, --ballots <B>         Number of ballots to cast [default: 50]
  -s, --spoil <S>           Number of ballots to spoil [default: 5]
      --contests <C>        Number of contests [default: 3]
      --candidates <MAX>    Max candidates per contest [default: 5]
      --seed <SEED>         Random seed for reproducibility (omit for random)
      --json                Output election record as JSON
      --verbose             Verbose progress output
  -q, --quiet               Only show final result
  -h, --help                Print help
```

## Examples

**Quick test** (~60 seconds):
```bash
cargo run --release -- --guardians 3 --threshold 2 --ballots 5 --spoil 1 --seed 42
```

**Reproducible simulation** (same seed = same results):
```bash
cargo run --release -- --ballots 10 --seed 12345
cargo run --release -- --ballots 10 --seed 12345  # identical output
```

**Larger election** (~8 minutes):
```bash
cargo run --release -- --guardians 5 --threshold 3 --ballots 50 --contests 5 --candidates 8
```

**Verbose output** (shows per-guardian Schnorr proof verification):
```bash
cargo run --release -- --ballots 10 --seed 42 --verbose
```

**JSON election record**:
```bash
cargo run --release -- --ballots 10 --seed 42 --json > election-record.json
```

## What It Does

The simulator runs six phases that mirror a real ElectionGuard election:

### Phase 1: Manifest Generation

Builds a randomized election manifest:
- First contest is always "President" (pick 1)
- Remaining contests are randomly "pick 1" or "pick up to 2"
- Each contest gets 2 to `--candidates` randomly named candidates
- One ballot style and geopolitical unit

### Phase 2: Key Ceremony

Performs the full threshold key ceremony:
- Each guardian generates an ElGamal key pair and polynomial coefficients
- All guardians exchange encrypted Shamir secret shares (n^2 exchanges)
- Each guardian verifies every received share against public commitments
- Schnorr proofs are generated and verified for all guardian keys
- Joint election key is computed from all guardians' public keys
- Election context is built with the full hash chain (H_P -> H_B -> H_E)

### Phase 3: Ballot Encryption

Encrypts all ballots through an EncryptionMediator:
- Generates random but valid vote patterns for each ballot
- Pick-1 contests: exactly one candidate selected
- Pick-N contests: 0 to N candidates selected randomly
- Each encrypted ballot includes disjunctive Chaum-Pedersen proofs
  (each selection encrypts 0 or 1) and constant proofs (contest sums
  match the allowed votes)
- First `--ballots` are cast, last `--spoil` are spoiled
- Tracks expected plaintext totals for cast ballots only

### Phase 4: Homomorphic Tally

Accumulates ciphertexts from cast ballots:
- Multiplies ElGamal pads and data values per selection per contest
- The accumulated ciphertext encrypts the sum of all individual votes
- No decryption needed -- pure ciphertext arithmetic

### Phase 5: Threshold Decryption

Decrypts the tally using k-of-n threshold decryption:
- First `--threshold` guardians participate (remaining are "absent")
- Each participating guardian computes partial decryption shares
  for every tally entry
- Lagrange interpolation combines the partial shares
- Baby-step/giant-step discrete log recovers the plaintext count
  from g^count
- Chaum-Pedersen proofs prove each partial decryption is correct

### Phase 6: Verification

Verifies every proof and the final tally:
- All ballot encryption proofs (disjunctive + constant) are re-verified
- All decryption proofs are verified
- Decrypted tally is compared against the expected plaintext totals
- Results are printed in a formatted table

## Sample Output

```
Election manifest: 3 contests, 11 candidates
Key ceremony complete: 3-of-2 threshold, joint key established
Encrypted 12 ballots: 10 cast, 2 spoiled
All 12 ballot proofs verified
Tally accumulated from 10 cast ballots
Decryption complete using guardians guardian-1, guardian-2

=== ELECTION RESULTS ===

Contest: President (pick 1)
  Henry Taylor                    4 votes
  Leo Jackson                     6 votes
  Total                          10 votes  OK

Contest: Measure C (pick 1)
  Karen Thomas                    2 votes
  Irene Davis                     3 votes
  Frank Wilson                    1 votes
  Eva Martinez                    0 votes
  Carol Williams                  1 votes
  Total                          10 votes  OK

Contest: Amendment 1 (pick up to 2)
  David Brown                     2 votes
  Alice Johnson                   2 votes
  Grace Lee                       3 votes
  James Anderson                  1 votes
  Total                           8 votes  OK

=== VERIFICATION ===
Ballot encryption proofs:  12/12 valid  OK
Decryption proofs:         22/22 valid  OK
Tally matches expected:    Yes  OK
Spoiled ballot count:      2

Election simulation PASSED
Total time: 104.28s
```

## Performance Notes

Each ballot requires multiple 4096-bit modular exponentiations for encryption
and proof generation. Approximate times in `--release` mode on a single core:

| Ballots | Guardians | Threshold | Approximate Time |
|---------|-----------|-----------|-----------------|
| 5       | 3         | 2         | ~60s            |
| 10      | 3         | 2         | ~100s           |
| 50      | 3         | 2         | ~8 min          |
| 50      | 5         | 3         | ~10 min         |

The simulation is single-threaded. Real deployments would parallelize ballot
encryption across multiple devices.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Simulation passed -- all proofs valid, tally matches |
| 1    | Simulation failed -- proof verification or tally mismatch |