package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.antiexfil.AntiExfilCoordinator;
import com.sparrowwallet.drongo.antiexfil.AntiExfilException;
import com.sparrowwallet.drongo.antiexfil.AntiExfilNetwork;
import com.sparrowwallet.drongo.antiexfil.AntiExfilStage;
import com.sparrowwallet.sparrow.io.AntiExfilCarriage;

import java.util.Optional;

/**
 * Drives the four-stage ceremony against one signing device.
 *
 * Carriage is now a parameter rather than a hardcoded envelope. The stage
 * sequence, the pre-reveal cancellation rule, the post-reveal abort recording
 * and the exact-retry loop are unchanged and identical for every profile,
 * because they are properties of the protocol rather than of the transport.
 *
 * This is what allows a multisig where one cosigner is a SeedSigner speaking
 * AEXT and another is a Jade speaking in-PSBT records: each keystore selects
 * its carriage, and the coordinator sees the same AEXB messages either way.
 */
public final class AntiExfilSigningFlow {
    private AntiExfilSigningFlow() {
    }

    /** Detached AEXT carriage, the existing default. */
    public static Result execute(AntiExfilCoordinator coordinator, AntiExfilNetwork network, Exchange exchange) {
        return execute(coordinator, network, exchange, AntiExfilCarriage.Aext.INSTANCE);
    }

    public static Result execute(AntiExfilCoordinator coordinator, AntiExfilNetwork network,
                                 Exchange exchange, AntiExfilCarriage carriage) {
        return execute(new CoordinatorSession(coordinator), network, exchange, carriage);
    }

    /** Session-level entry point, defaulting to the detached AEXT carriage. */
    static Result execute(Session session, AntiExfilNetwork network, Exchange exchange) {
        return execute(session, network, exchange, AntiExfilCarriage.Aext.INSTANCE);
    }

    static Result execute(Session session, AntiExfilNetwork network, Exchange exchange,
                          AntiExfilCarriage carriage) {
        AntiExfilCoordinator.Phase phase = session.phase();
        if(phase == AntiExfilCoordinator.Phase.COMPLETE) {
            return new Result(Outcome.COMPLETE, session.completedResult());
        }

        byte[] frozenPsbt = session.frozenPsbt();
        byte[] commitBytes = session.hostCommitMessage();
        byte[] revealBytes;

        if(phase == AntiExfilCoordinator.Phase.COMMITMENTS_CREATED) {
            AntiExfilCarriage.Payload commit = carriage.request(commitBytes, frozenPsbt);
            if(!exchange.display(commit)) return new Result(Outcome.CANCELLED_BEFORE_REVEAL, null);
            Optional<AntiExfilCarriage.Payload> scanned =
                    exchange.scan(AntiExfilStage.SIGNER_OPENINGS, network, carriage);
            if(scanned.isEmpty()) return new Result(Outcome.CANCELLED_BEFORE_REVEAL, null);
            try {
                byte[] openings = carriage.response(scanned.get(), AntiExfilStage.SIGNER_OPENINGS,
                        network, commitBytes, frozenPsbt);
                revealBytes = session.acceptOpenings(openings);
            } catch(AntiExfilException e) {
                if(AntiExfilCoordinator.isSignerDataRejection(e)) session.recordSignerDataRejection();
                throw e;
            }
        } else {
            revealBytes = session.hostRevealMessage();
        }

        AntiExfilCarriage.Payload reveal = carriage.request(revealBytes, frozenPsbt);
        while(true) {
            if(!exchange.display(reveal)) {
                if(exchange.onPostRevealInterruption() == PostRevealAction.RETRY_EXACT) continue;
                session.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.USER_ABANDONED);
                return new Result(Outcome.ABORTED_AFTER_REVEAL, null);
            }
            Optional<AntiExfilCarriage.Payload> scanned =
                    exchange.scan(AntiExfilStage.SIGNER_SIGNATURES, network, carriage);
            if(scanned.isEmpty()) {
                if(exchange.onPostRevealInterruption() == PostRevealAction.RETRY_EXACT) continue;
                session.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.TRANSPORT_FAILED);
                return new Result(Outcome.ABORTED_AFTER_REVEAL, null);
            }
            try {
                byte[] signatures = carriage.response(scanned.get(), AntiExfilStage.SIGNER_SIGNATURES,
                        network, revealBytes, frozenPsbt);
                AntiExfilCoordinator.Completion completion = session.complete(signatures);
                return new Result(Outcome.COMPLETE, completion);
            } catch(AntiExfilException e) {
                if(AntiExfilCoordinator.isSignerDataRejection(e)) session.recordSignerDataRejection();
                throw e;
            }
        }
    }

    /**
     * The scanner is told which carriage to expect so it can restrict itself to
     * one UR type. A protected scan must never fall back to ordinary PSBT
     * handling, and with two profiles in play it must not accept the other
     * profile's type either.
     */
    public interface Exchange {
        boolean display(AntiExfilCarriage.Payload payload);
        Optional<AntiExfilCarriage.Payload> scan(AntiExfilStage expectedStage,
                                                  AntiExfilNetwork expectedNetwork,
                                                  AntiExfilCarriage carriage);
        PostRevealAction onPostRevealInterruption();
    }

    interface Session {
        AntiExfilCoordinator.Phase phase();
        byte[] frozenPsbt();
        byte[] hostCommitMessage();
        byte[] acceptOpenings(byte[] message);
        byte[] hostRevealMessage();
        AntiExfilCoordinator.Completion complete(byte[] message);
        AntiExfilCoordinator.Completion completedResult();
        void recordPostRevealAbort(AntiExfilCoordinator.AbortReason reason);
        void recordSignerDataRejection();
    }

    private record CoordinatorSession(AntiExfilCoordinator coordinator) implements Session {
        @Override public AntiExfilCoordinator.Phase phase() { return coordinator.getStatus().getPhase(); }
        @Override public byte[] frozenPsbt() { return coordinator.getFrozenPsbt(); }
        @Override public byte[] hostCommitMessage() { return coordinator.getHostCommitMessage(); }
        @Override public byte[] acceptOpenings(byte[] message) { return coordinator.acceptOpenings(message); }
        @Override public byte[] hostRevealMessage() { return coordinator.getHostRevealMessage(); }
        @Override public AntiExfilCoordinator.Completion complete(byte[] message) { return coordinator.complete(message); }
        @Override public AntiExfilCoordinator.Completion completedResult() { return coordinator.getCompletedResult(); }
        @Override public void recordPostRevealAbort(AntiExfilCoordinator.AbortReason reason) { coordinator.recordPostRevealAbort(reason); }
        @Override public void recordSignerDataRejection() { coordinator.recordSignerDataRejection(); }
    }

    public enum PostRevealAction {
        RETRY_EXACT,
        ABANDON
    }

    public enum Outcome {
        COMPLETE,
        CANCELLED_BEFORE_REVEAL,
        ABORTED_AFTER_REVEAL
    }

    public record Result(Outcome outcome, AntiExfilCoordinator.Completion completion) {
    }
}
