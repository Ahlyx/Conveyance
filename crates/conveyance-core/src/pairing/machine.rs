//! The PC-side pairing state machine, pure logic.
//!
//! States and transitions come verbatim from the spec's "Pairing
//! ceremony (PC side)" diagram, with one documented interpretation: ANY
//! rejection or timeout at AWAITING_CONFIRM (invalid signature, replayed
//! nonce) returns to UNPAIRED and BURNS the nonce ("single-use even on
//! failure"). A fresh attempt means a fresh `conveyance pair` run with a
//! fresh QR -- one QR per invocation is a recorded phase-6 decision.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingState {
    Unpaired,
    QrDisplayed,
    Connecting,
    AwaitingConfirm,
    AckSent,
    Paired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// `conveyance pair` invoked; QR generated and displayed.
    BeginPairing,
    /// 60s elapsed with no matching advertisement.
    QrExpired,
    /// An advertisement matched the service UUID.
    AdvertisementSeen,
    /// The connect/discover/subscribe sequence failed.
    ConnectFailed,
    /// Link established; now awaiting the confirm message.
    GattConnected,
    /// 10s without a confirm arriving.
    ConfirmTimeout,
    /// Confirm arrived but failed validation (sig/replay/version).
    InvalidConfirm,
    /// Confirm verified against our QR values.
    ValidConfirmReceived,
    /// The signed Ack could not be written to the link.
    AckWriteFailed,
    /// Ack written successfully.
    AckWrittenOk,
    /// Ctrl-C / user cancelled.
    UserAborted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionError {
    Illegal { from: PairingState, event: Event },
}

/// The single authority for pairing-state changes on the PC.
pub fn step(state: PairingState, event: Event) -> Result<PairingState, TransitionError> {
    use Event::*;
    use PairingState::*;

    match (state, event) {
        // Entry point only from UNPAIRED.
        (Unpaired, BeginPairing) => Ok(QrDisplayed),

        // Waiting for the phone to advertise.
        (QrDisplayed, AdvertisementSeen) => Ok(Connecting),
        (QrDisplayed, QrExpired) => Ok(Unpaired),
        (QrDisplayed, UserAborted) => Ok(Unpaired),

        // BLE failure sends us back to waiting for an advertisement
        // (same QR stays valid until its own expiry).
        (Connecting, ConnectFailed) => Ok(QrDisplayed),
        (Connecting, GattConnected) => Ok(AwaitingConfirm),
        (Connecting, UserAborted) => Ok(Unpaired),

        // Confirm handling. Every failure mode here burns the nonce:
        // back to UNPAIRED, per "single-use even on failure".
        (AwaitingConfirm, ValidConfirmReceived) => Ok(AckSent),
        (AwaitingConfirm, InvalidConfirm) => Ok(Unpaired),
        (AwaitingConfirm, ConfirmTimeout) => Ok(Unpaired),
        (AwaitingConfirm, UserAborted) => Ok(Unpaired),

        // Ack outcome decides PAIRED vs UNPAIRED.
        (AckSent, AckWrittenOk) => Ok(Paired),
        (AckSent, AckWriteFailed) => Ok(Unpaired),

        // Everything else is illegal, including touching a completed or
        // aborted ceremony.
        (state, event) => Err(TransitionError::Illegal { from: state, event }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Event::*;
    use PairingState::*;

    fn ok(from: PairingState, event: Event, to: PairingState) {
        assert_eq!(step(from, event), Ok(to), "{from:?} + {event:?}");
    }

    #[allow(dead_code)]
    fn illegal(from: PairingState, event: Event) {
        assert_eq!(
            step(from, event),
            Err(TransitionError::Illegal { from, event }),
            "{from:?} + {event:?} must be illegal"
        );
    }

    /// Full matrix per the spec diagram plus the recorded abort rule.
    #[test]
    fn full_matrix_matches_spec() {
        let all_events = [
            BeginPairing,
            QrExpired,
            AdvertisementSeen,
            ConnectFailed,
            GattConnected,
            ConfirmTimeout,
            InvalidConfirm,
            ValidConfirmReceived,
            AckWriteFailed,
            AckWrittenOk,
            UserAborted,
        ];

        // Legal cells first.
        ok(Unpaired, BeginPairing, QrDisplayed);
        ok(QrDisplayed, AdvertisementSeen, Connecting);
        ok(QrDisplayed, QrExpired, Unpaired);
        ok(QrDisplayed, UserAborted, Unpaired);
        ok(Connecting, ConnectFailed, QrDisplayed);
        ok(Connecting, GattConnected, AwaitingConfirm);
        ok(Connecting, UserAborted, Unpaired);
        ok(AwaitingConfirm, ValidConfirmReceived, AckSent);
        ok(AwaitingConfirm, InvalidConfirm, Unpaired);
        ok(AwaitingConfirm, ConfirmTimeout, Unpaired);
        ok(AwaitingConfirm, UserAborted, Unpaired);
        ok(AckSent, AckWrittenOk, Paired);
        ok(AckSent, AckWriteFailed, Unpaired);

        // Every other cell must be illegal. Walk all combinations and
        // skip exactly the legal ones asserted above.
        let legal = [
            (Unpaired, BeginPairing),
            (QrDisplayed, AdvertisementSeen),
            (QrDisplayed, QrExpired),
            (QrDisplayed, UserAborted),
            (Connecting, ConnectFailed),
            (Connecting, GattConnected),
            (Connecting, UserAborted),
            (AwaitingConfirm, ValidConfirmReceived),
            (AwaitingConfirm, InvalidConfirm),
            (AwaitingConfirm, ConfirmTimeout),
            (AwaitingConfirm, UserAborted),
            (AckSent, AckWrittenOk),
            (AckSent, AckWriteFailed),
        ];
        for state in [
            Unpaired,
            QrDisplayed,
            Connecting,
            AwaitingConfirm,
            AckSent,
            Paired,
        ] {
            for event in all_events {
                if legal.contains(&(state, event)) {
                    continue;
                }
                assert!(
                    step(state, event).is_err(),
                    "{state:?} + {event:?} should be illegal"
                );
            }
        }
        // And PAIRED is terminal for everything.
        for event in all_events {
            assert!(step(Paired, event).is_err(), "{event:?} after PAIRED");
        }
    }

    #[test]
    fn happy_path_walk() {
        let mut s = Unpaired;
        s = step(s, BeginPairing).unwrap();
        s = step(s, AdvertisementSeen).unwrap();
        s = step(s, GattConnected).unwrap();
        s = step(s, ValidConfirmReceived).unwrap();
        s = step(s, AckWrittenOk).unwrap();
        assert_eq!(s, Paired);
    }

    #[test]
    fn ble_failure_returns_to_qr_displayed_same_code_still_live() {
        let s = step(QrDisplayed, AdvertisementSeen).unwrap();
        let s = step(s, ConnectFailed).unwrap();
        assert_eq!(s, QrDisplayed, "same QR remains valid after BLE hiccup");
    }
}
