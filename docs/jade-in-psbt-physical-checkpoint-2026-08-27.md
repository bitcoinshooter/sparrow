# Jade in-PSBT physical checkpoint

Recorded 2026-08-27 on Testnet4, in an isolated Sparrow profile, against an
unmodified `AntiExfilCoordinator` at `e9a692a`.

## Result

A DIY Blockstream Jade running interactive anti-exfil firmware completed a full
four-stage ceremony through the coordinator, carried entirely in PSBTs rather
than AEXT envelopes. The transaction was verified and broadcast.

Txid: `4879f94328c2f933b344c14231e4b4023729bb8a514eedec3899c95f6a40215d`

Single-signature P2WPKH, one input, one P2TR output. The wallet keystore was
imported by QR as an airgapped hardware keystore and set to Protected signing:
Optional.

## What differed from the detached profile

Only the carriage. The coordinator, the durable session, the abort journal and
the crypto were untouched. Jade received animated `crypto-psbt` URs carrying a
PSBT with BIP-174 proprietary `0xFC` records under identifier `ae`, and returned
PSBTs the same way. The coordinator saw canonical AEXB messages at every stage,
because the in-PSBT profile maps between the two.

## Stored transcript

The persisted session reached phase COMPLETE and holds all four messages:

- message 1, 183 bytes, stage 1 HOST_COMMIT, 1 slot
- message 2, 216 bytes, stage 2 SIGNER_OPENINGS, 1 slot
- message 3, 248 bytes, stage 3 HOST_REVEAL, 1 slot
- message 4, 280 bytes, stage 4 SIGNER_SIGNATURES, 1 slot

Each length is the 78-byte AEXB header plus one record of 105, 138, 170 and 202
bytes respectively. All four carry the same session identifier
`a1d338270a2cf8fd466cc4a7...`, the same PSBT digest
`49ec0bbdee881e18afb12db6...`, the same signer public key, the same message hash
and the same host commitment.

Frozen PSBT: 303 bytes, SHA-256 `49ec0bbdee881e18afb12db6c030d2f777ca164bc996f37acdcf45653b397fd2`,
matching the digest in every message header.

Signed PSBT: 411 bytes, SHA-256 `6b005345058e30825aa8a106ac41c6dbf9b0ac262e21de8ad2b278577d77b332`.

Abort journal: 0 events. No post-reveal abandonment was recorded.

## Independent verification

Checked outside both implementations, from the session file bytes alone, with
tooling sharing no code with the Java or the firmware:

- the host commitment re-derives as `tagged_hash("s2c/ecdsa/data", rho)` from the
  randomness revealed at stage 3
- the sign-to-contract relation holds: the signature's `r` equals the
  x-coordinate of `opening + tweak * G`
- the signature is valid ECDSA for the expected public key over the expected
  sighash, and is low-S
- the signer opening is byte-identical across messages 2, 3 and 4, so the device
  did not move its nonce commitment between stages
- the signature in message 4, DER-encoded with sighash byte `0x01`, appears
  verbatim in both the stored signed PSBT and the broadcast transaction

## Negative gate: device-side reveal check

Anti-exfil is two-directional. The coordinator checks that the device folded in
the host randomness; the device must check that the coordinator did not choose
that randomness after seeing the device's nonce commitment. Nothing in the
ceremony above exercises the second half, since an honest coordinator never
sends a bad reveal.

Tested directly. A temporary hook in the carriage flipped one byte of the
revealed randomness at stage 3, after the coordinator had produced a valid
message, so no coordinator validation was bypassed or modified. The commitment
sent at stage 1 therefore no longer opened to the randomness revealed at stage
3.

Jade refused, reporting:

    AE host entropy doesn't match commitment

No signature was produced. The device re-derives
`tagged_hash("s2c/ecdsa/data", rho)` and compares it to the host commitment it
was sent, so a coordinator cannot wait until it has seen the signer's nonce
commitment and only then select entropy it prefers.

The hook was reverted immediately and is not present on any branch.

## What this does not cover

Single-signature only: one slot, one input, one device. No multisig, no
SeedSigner, and therefore no mixed-carriage transaction. The negative gate
covers the device-side reveal check only; other refusal paths, such as a
changed transaction or a stripped record, were not exercised on hardware. A ceremony where a Jade
and a SeedSigner cosign the same transaction through different profiles is the
next checkpoint and has not been attempted.

The device-side firmware is a personal build, not a released Jade image.
