# Jade adversarial signer checkpoint

Recorded 2026-08-27 on Testnet4, in an isolated Sparrow profile, against an
unmodified `AntiExfilCoordinator` at `e9a692a`, carried in PSBTs.

Firmware: Jade `b54ca0be` on a Waveshare Touch LCD 2 board, built with
`CONFIG_DEBUG_MODE`. The debug build exposes a `debug_set_ae_cheat` RPC that
selects a misbehaving signing path. It is compiled out of production builds.

## Why

The honest ceremony and the corrupted-reveal gate together show that the device
folds in host randomness and refuses a reveal that does not open the commitment.
Neither shows that the coordinator catches a signer that is actually dishonest.
That is the direction anti-exfil exists to protect, and it can only be shown
with a device that genuinely misbehaves rather than with a mutated fixture.

Three cheat modes were run, each on a fresh session with the same wallet key.

## 1. ignore_entropy

The device signs with plain ECDSA, ignoring the revealed host randomness
entirely. The signature carries no sign-to-contract structure.

Rejected. `SIGNATURE_INVALID: Anti-exfil signature verification failed`.

## 2. biased_nonce

The harder case, and the one that matters. The device still calls
`wally_ae_sig_from_bytes`, so it produces a structurally valid sign-to-contract
signature. But it substitutes its own entropy for the host's and grinds,
incrementing that entropy until the resulting signature satisfies a chosen
predicate on its bytes. Nothing about the message is malformed and the
construction is internally consistent.

This is a working covert channel: the grinding leaks several bits per signature
to anyone who knows the predicate.

Rejected. Catching it requires verifying the relation against the coordinator's
own randomness rather than confirming that the signature is internally
well-formed.

## 3. wrong_commit

The device returns a signer commitment derived from the wrong hash at stage 2,
then signs honestly at stage 4. The signature is a valid sign-to-contract
signature over the correct host randomness; it simply does not open to the
commitment the device claimed earlier.

Rejected at stage 4, where the relation is checked against the stored opening.

## Abort journal

Each rejection was recorded durably against the wallet key identity
`c882a0c7d7029ff2c2f30babd33e492d590629f9d87d771fa3e129eedda1b6ea`:

    events: 3
      [0] 2026-08-27 17:37:46  SIGNATURE_REJECTED  session c189e0187421c571..
      [1] 2026-08-27 17:42:25  SIGNATURE_REJECTED  session 914000b639d1b37f..
      [2] 2026-08-27 17:45:45  SIGNATURE_REJECTED  session 782f31e78fed0a04..

Three distinct sessions, each bound to its own PSBT digest and timestamp. The
journal grew 73, 165, 257, 349 bytes across the run, one 92-byte record per
rejection.

After the first event, starting a fresh session raised the selective-abort
warning, which had to be acknowledged explicitly before a new challenge could
begin. That escalation path had not previously been exercised on hardware.

## What this does not cover

Single-signature, one slot, one input. The cheat modes were driven over USB
while the ceremony ran over QR; the modes live in RAM and reset on reboot.

The predicate used by `biased_nonce` is a fixed test pattern, not an attempt to
extract key material. Demonstrating actual key recovery from ground nonces was
not attempted and is not necessary to show that the check works.

No claim is made that this exhausts the ways a signer can misbehave. It covers
three: no sign-to-contract structure, valid structure over substituted entropy,
and honest signing against a falsified commitment.
