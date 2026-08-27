package com.sparrowwallet.sparrow.io;

import com.sparrowwallet.drongo.antiexfil.AntiExfilCodec;
import com.sparrowwallet.drongo.antiexfil.AntiExfilInPsbtProfile;
import com.sparrowwallet.drongo.antiexfil.AntiExfilMessage;
import com.sparrowwallet.drongo.antiexfil.AntiExfilNetwork;
import com.sparrowwallet.drongo.antiexfil.AntiExfilStage;

import java.util.Arrays;

import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.INVALID_MESSAGE;
import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.TRANSACTION_MISMATCH;

/**
 * How a protocol message reaches a signing device.
 *
 * The four-stage transcript, the slot set, the crypto and the coordinator are
 * the protocol. Carriage is how the bytes travel, and two exist:
 *
 *   AEXT      the detached profile - a self-describing envelope carrying the
 *             AEXB message, with the PSBT alongside it in requests and absent
 *             from responses. SeedSigner and Kern speak this.
 *   in-PSBT   BIP-174 proprietary 0xFC records under identifier "ae", written
 *             into the PSBT itself. Jade speaks this.
 *
 * Both reduce to the same AntiExfilMessage, so AntiExfilCoordinator, the
 * durable session and the abort journal are untouched by the choice. That is
 * the substance of the claim that these are profiles over one protocol rather
 * than two protocols, and it is what lets a wallet run a Jade and a SeedSigner
 * as cosigners of the same transaction: carriage is a property of the keystore,
 * not of the ceremony.
 *
 * <h2>What the two profiles do not share</h2>
 *
 * AEXT gets a structural guarantee free: responses carry no PSBT, so a signer
 * cannot propose a transaction. The in-PSBT profile returns a whole PSBT and
 * recovers the same property by construction, taking only the response field
 * from the reply and everything else from coordinator state. Neither profile
 * lets signer-returned data reach the coordinator's frozen transaction.
 */
public interface AntiExfilCarriage {

    /** A displayable payload and the UR type it should be encoded as. */
    record Payload(String urType, byte[] bytes, AntiExfilStage stage) {
        public Payload {
            bytes = bytes.clone();
        }

        @Override
        public byte[] bytes() {
            return bytes.clone();
        }
    }

    /** Human-readable profile name, for logs and for the keystore UI. */
    String getName();

    /** The UR type this profile scans and displays. */
    String getUrType();

    /**
     * Encode a coordinator request (stage 1 or 3) for display.
     *
     * @param encodedMessage the canonical AEXB message from the coordinator
     * @param frozenPsbt     the coordinator's exact frozen transaction bytes
     */
    Payload request(byte[] encodedMessage, byte[] frozenPsbt);

    /**
     * Decode a signer response (stage 2 or 4) back to a canonical AEXB message.
     *
     * @param payload             what the scanner produced
     * @param expectedStage       the only stage that may be accepted here
     * @param expectedNetwork     the active user-visible network
     * @param previousMessage     the coordinator's own preceding message; the
     *                            in-PSBT profile needs it as the authority for
     *                            everything the reply is not entitled to supply
     * @param frozenPsbt          the coordinator's exact frozen transaction
     */
    byte[] response(Payload payload, AntiExfilStage expectedStage, AntiExfilNetwork expectedNetwork,
                    byte[] previousMessage, byte[] frozenPsbt);

    /**
     * Which profile a device speaks.
     *
     * Carriage is a property of the signing device, so it is selected from the
     * keystore rather than chosen per transaction. A wallet can therefore hold
     * a Jade and a SeedSigner as cosigners and run each through its own
     * profile against the same coordinator.
     *
     * Only devices known to implement a profile are mapped. Anything else
     * returns null, and the caller must treat that as unsupported rather than
     * guessing: presenting a protected ceremony to a device that cannot answer
     * it wastes a session and, worse, teaches a user that protected signing is
     * unreliable.
     */
    public static AntiExfilCarriage forKeystore(com.sparrowwallet.drongo.wallet.Keystore keystore) {
        if(keystore == null || keystore.getWalletModel() == null) {
            return null;
        }
        return switch(keystore.getWalletModel()) {
            case SEEDSIGNER -> Aext.INSTANCE;
            case JADE -> InPsbt.INSTANCE;
            default -> null;
        };
    }

    /**
     * The detached profile. Delegates to AntiExfilTransportPackage, which owns
     * the AEXT envelope, its digest cross-checks and its stage/PSBT invariant.
     */
    final class Aext implements AntiExfilCarriage {
        public static final AntiExfilCarriage INSTANCE = new Aext();

        private Aext() {
        }

        @Override
        public String getName() {
            return "Detached (AEXT)";
        }

        @Override
        public String getUrType() {
            return AntiExfilTransportPackage.UR_TYPE;
        }

        @Override
        public Payload request(byte[] encodedMessage, byte[] frozenPsbt) {
            AntiExfilMessage message = AntiExfilCodec.decode(encodedMessage);
            AntiExfilTransportPackage transportPackage =
                    new AntiExfilTransportPackage(message, frozenPsbt);
            // Round-trip so what is displayed is exactly what a scanner will parse.
            byte[] encoded = transportPackage.encode();
            AntiExfilTransportPackage.decode(encoded);
            return new Payload(getUrType(), encoded, message.getStage());
        }

        @Override
        public byte[] response(Payload payload, AntiExfilStage expectedStage,
                               AntiExfilNetwork expectedNetwork, byte[] previousMessage,
                               byte[] frozenPsbt) {
            AntiExfilTransportPackage received = AntiExfilTransportPackage.decode(payload.bytes());
            AntiExfilTransportPackage canonical =
                    AntiExfilTransportPackage.decode(received.encode());
            canonical.require(expectedStage, expectedNetwork);
            return AntiExfilCodec.encode(canonical.getMessage());
        }
    }

    /**
     * The in-PSBT profile. The payload is the PSBT itself, so it travels as an
     * ordinary crypto-psbt UR that existing signers already understand.
     */
    final class InPsbt implements AntiExfilCarriage {
        public static final AntiExfilCarriage INSTANCE = new InPsbt();
        public static final String UR_TYPE = "crypto-psbt";

        private InPsbt() {
        }

        @Override
        public String getName() {
            return "In-PSBT (0xFC \"ae\")";
        }

        @Override
        public String getUrType() {
            return UR_TYPE;
        }

        @Override
        public Payload request(byte[] encodedMessage, byte[] frozenPsbt) {
            AntiExfilMessage message = AntiExfilCodec.decode(encodedMessage);
            byte[] psbt = AntiExfilInPsbtProfile.encodeRequest(message, frozenPsbt);
            return new Payload(getUrType(), psbt, message.getStage());
        }

        @Override
        public byte[] response(Payload payload, AntiExfilStage expectedStage,
                               AntiExfilNetwork expectedNetwork, byte[] previousMessage,
                               byte[] frozenPsbt) {
            if(previousMessage == null) {
                throw new com.sparrowwallet.drongo.antiexfil.AntiExfilException(INVALID_MESSAGE,
                        "The in-PSBT profile needs the coordinator's preceding message to read a reply");
            }
            AntiExfilMessage previous = AntiExfilCodec.decode(previousMessage);
            AntiExfilMessage response =
                    AntiExfilInPsbtProfile.decodeResponse(previous, frozenPsbt, payload.bytes());

            // The stage and network checks AEXT gets from its own header have to
            // be made explicitly here, because a PSBT carries neither.
            if(response.getStage() != expectedStage) {
                throw new com.sparrowwallet.drongo.antiexfil.AntiExfilException(
                        com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.WRONG_STAGE,
                        "Expected stage " + expectedStage + ", reply produced " + response.getStage());
            }
            if(response.getNetwork() != expectedNetwork) {
                throw new com.sparrowwallet.drongo.antiexfil.AntiExfilException(TRANSACTION_MISMATCH,
                        "Reply is for another network");
            }
            byte[] encoded = AntiExfilCodec.encode(response);
            // Canonicality, mirroring what AEXT enforces on its own envelope.
            if(!Arrays.equals(encoded, AntiExfilCodec.encode(AntiExfilCodec.decode(encoded)))) {
                throw new com.sparrowwallet.drongo.antiexfil.AntiExfilException(INVALID_MESSAGE,
                        "Lifted message is not canonically encoded");
            }
            return encoded;
        }
    }
}
