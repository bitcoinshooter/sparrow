package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.antiexfil.AntiExfilNetwork;
import com.sparrowwallet.drongo.antiexfil.AntiExfilStage;
import com.sparrowwallet.hummingbird.UR;
import com.sparrowwallet.sparrow.AppServices;
import com.sparrowwallet.sparrow.control.QRDisplayDialog;
import com.sparrowwallet.sparrow.control.QREncoding;
import com.sparrowwallet.sparrow.control.QRScanDialog;
import com.sparrowwallet.sparrow.io.AntiExfilCarriage;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.stage.Window;

import java.util.Arrays;
import java.util.Optional;

/**
 * Displays and scans anti-exfil payloads over animated QR, for either profile.
 *
 * The dialog is carriage-neutral: it works in UR type and raw bytes, and never
 * inspects the protocol content. Structural and semantic validation belongs to
 * the carriage and to the coordinator, which is why a scan here returns bytes
 * rather than a parsed message.
 *
 * The scanner is pinned to exactly one UR type per stage. With two profiles
 * live this matters more than it did with one: a protected scan must not fall
 * through to ordinary PSBT handling, and it must not accept the other profile's
 * type either, or a device could answer a ceremony it was never asked to join.
 */
public final class AntiExfilQrExchange implements AntiExfilSigningFlow.Exchange {
    private final Window owner;
    private final String deviceLabel;

    public AntiExfilQrExchange(Window owner) {
        this(owner, "your signing device");
    }

    public AntiExfilQrExchange(Window owner, String deviceLabel) {
        this.owner = owner;
        this.deviceLabel = deviceLabel;
    }

    @Override
    public boolean display(AntiExfilCarriage.Payload payload) {
        try {
            UR ur = UR.fromBytes(payload.urType(), payload.bytes());
            QRDisplayDialog dialog = new QRDisplayDialog(ur, null, false, true, QREncoding.UR);
            dialog.setTitle("Anti-exfil signing");
            dialog.setHeaderText(payload.stage() == AntiExfilStage.HOST_COMMIT
                    ? "Step 1 of 2: scan this commitment with " + deviceLabel
                    : "Step 2 of 2: scan this host reveal with " + deviceLabel);
            dialog.initOwner(owner);
            Optional<ButtonType> result = dialog.showAndWait();
            return result.isPresent() && result.get().getButtonData() == ButtonBar.ButtonData.OK_DONE;
        } catch(UR.URException e) {
            AppServices.showErrorDialog("Cannot display anti-exfil QR", e.getMessage());
            return false;
        }
    }

    @Override
    public Optional<AntiExfilCarriage.Payload> scan(AntiExfilStage expectedStage,
                                                     AntiExfilNetwork expectedNetwork,
                                                     AntiExfilCarriage carriage) {
        QRScanDialog dialog = new QRScanDialog(carriage.getUrType());
        dialog.setTitle("Anti-exfil signing");
        dialog.setHeaderText(expectedStage == AntiExfilStage.SIGNER_OPENINGS
                ? "Scan nonce openings from " + deviceLabel
                : "Scan verified signatures from " + deviceLabel);
        dialog.initOwner(owner);

        Optional<QRScanDialog.Result> result = dialog.showAndWait();
        if(result.isEmpty()) {
            return Optional.empty();
        }
        if(result.get().exception != null || result.get().getUr() == null) {
            AppServices.showErrorDialog("Invalid anti-exfil QR",
                    result.get().exception == null
                            ? "Scanner returned no ur:" + carriage.getUrType()
                            : result.get().exception.getMessage());
            return Optional.empty();
        }

        UR ur = result.get().getUr();
        if(!carriage.getUrType().equals(ur.getType())) {
            AppServices.showErrorDialog("Invalid anti-exfil QR",
                    "Expected ur:" + carriage.getUrType() + " but received ur:" + ur.getType());
            return Optional.empty();
        }
        try {
            // Non-canonical CBOR is rejected before the bytes reach the protocol,
            // so a signer cannot encode the same message two ways.
            byte[] payload = ur.toBytes();
            UR canonical = UR.fromBytes(ur.getType(), payload);
            if(!Arrays.equals(ur.getCborBytes(), canonical.getCborBytes())) {
                AppServices.showErrorDialog("Invalid anti-exfil QR",
                        "Anti-exfil UR uses non-canonical CBOR");
                return Optional.empty();
            }
            return Optional.of(new AntiExfilCarriage.Payload(ur.getType(), payload, expectedStage));
        } catch(UR.URException | IllegalArgumentException e) {
            AppServices.showErrorDialog("Invalid anti-exfil QR", e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public AntiExfilSigningFlow.PostRevealAction onPostRevealInterruption() {
        ButtonType retry = new ButtonType("Retry exact session", ButtonBar.ButtonData.YES);
        ButtonType abandon = new ButtonType("Abandon session", ButtonBar.ButtonData.NO);
        Optional<ButtonType> result = AppServices.showWarningDialog(
                "Protected signing is incomplete",
                "The host reveal has already been shown. Retry only this exact transaction and session. "
                        + "Starting fresh challenges after repeated signer failures can create a selective-abort channel.",
                retry, abandon);
        return result.isPresent() && result.get() == retry
                ? AntiExfilSigningFlow.PostRevealAction.RETRY_EXACT
                : AntiExfilSigningFlow.PostRevealAction.ABANDON;
    }
}
