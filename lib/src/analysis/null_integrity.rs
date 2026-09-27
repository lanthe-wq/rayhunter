use std::borrow::Cow;

use chrono::{DateTime, FixedOffset};

use pycrate_rs::nas::NASMessage;
use pycrate_rs::nas::emm::EMMMessage;
use pycrate_rs::nas::generated::emm::emm_security_mode_command::NASSecAlgoIntegAlgo::EPSIntegrityAlgorithmEIA0Null;
use telcom_parser::lte_rrc::SecurityAlgorithmConfigIntegrityProtAlgorithm;

use super::analyzer::{Analyzer, Event, EventType};
use super::information_element::{InformationElement, LteInformationElement};
use super::util::security_algorithm_configs;

/// 3GPP TS 33.401 only allows null integrity protection (EIA0) for unauthenticated
/// emergency calls, which Rayhunter never makes. A cell or MME selecting it
/// anyway lets whoever runs it inject or tamper with signalling messages.
pub struct NullIntegrityAnalyzer {}

impl Analyzer for NullIntegrityAnalyzer {
    fn get_name(&self) -> Cow<'_, str> {
        Cow::from("Null Integrity")
    }

    fn get_description(&self) -> Cow<'_, str> {
        Cow::from(
            "Tests whether the cell or MME requests null integrity protection (EIA0), which is only allowed for unauthenticated emergency calls",
        )
    }

    fn get_version(&self) -> u32 {
        1
    }

    fn analyze_information_element(
        &mut self,
        ie: &InformationElement,
        _packet_num: usize,
        _timestamp: DateTime<FixedOffset>,
    ) -> Option<Event> {
        let InformationElement::LTE(lte_ie) = ie else {
            return None;
        };
        match &**lte_ie {
            LteInformationElement::DlDcch(dcch_msg)
                if security_algorithm_configs(dcch_msg).iter().any(|config| {
                    config.integrity_prot_algorithm.0
                        == SecurityAlgorithmConfigIntegrityProtAlgorithm::EIA0_V920
                }) =>
            {
                Some(Event {
                    event_type: EventType::High,
                    message: "Cell requested null integrity protection (EIA0)".to_string(),
                })
            }
            LteInformationElement::NAS(NASMessage::EMMMessage(
                EMMMessage::EMMSecurityModeCommand(req),
            )) if req.nas_sec_algo.inner.integ_algo == EPSIntegrityAlgorithmEIA0Null => {
                Some(Event {
                    event_type: EventType::High,
                    message: "NAS security mode command requested null integrity protection (EIA0)"
                        .to_string(),
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::util::test_messages::{
        nas_security_mode_command, rrc_handover_reconfiguration, rrc_security_mode_command,
    };

    fn analyze(ie: &InformationElement) -> Option<Event> {
        NullIntegrityAnalyzer {}.analyze_information_element(ie, 0, DateTime::default())
    }

    #[test]
    fn test_rrc_security_mode_command() {
        let event = analyze(&rrc_security_mode_command(2, 0)).expect("expected a warning");
        assert_eq!(event.event_type, EventType::High);
        assert!(analyze(&rrc_security_mode_command(2, 2)).is_none());
        // a null cipher alone is the Null Cipher analyzer's business
        assert!(analyze(&rrc_security_mode_command(0, 2)).is_none());
    }

    #[test]
    fn test_rrc_handover_reconfiguration() {
        let event = analyze(&rrc_handover_reconfiguration(2, 0)).expect("expected a warning");
        assert_eq!(event.event_type, EventType::High);
        assert!(analyze(&rrc_handover_reconfiguration(2, 2)).is_none());
    }

    #[test]
    fn test_nas_security_mode_command() {
        let event = analyze(&nas_security_mode_command(2, 0)).expect("expected a warning");
        assert_eq!(event.event_type, EventType::High);
        assert!(analyze(&nas_security_mode_command(2, 2)).is_none());
        assert!(analyze(&nas_security_mode_command(0, 2)).is_none());
    }
}
