use std::borrow::Cow;

use chrono::{DateTime, FixedOffset};

use telcom_parser::lte_rrc::{CipheringAlgorithm_r12, DL_DCCH_Message, SCG_Configuration_r12};

use super::analyzer::{Analyzer, Event, EventType};
use super::information_element::{InformationElement, LteInformationElement};
use super::util::{
    rrc_connection_reconfiguration_r8, rrc_connection_reconfiguration_v1250,
    security_algorithm_configs,
};

pub struct NullCipherAnalyzer {}

impl NullCipherAnalyzer {
    fn check_scg_cipher(&self, msg: &DL_DCCH_Message) -> bool {
        let maybe_scg_configuration = rrc_connection_reconfiguration_r8(msg)
            .and_then(rrc_connection_reconfiguration_v1250)
            .and_then(|v1250| v1250.scg_configuration_r12.as_ref());
        let Some(SCG_Configuration_r12::Setup(scg_setup)) = maybe_scg_configuration else {
            return false;
        };
        let maybe_cipher = scg_setup
            .scg_config_part_scg_r12
            .as_ref()
            .and_then(|scg| scg.mobility_control_info_scg_r12.as_ref())
            .and_then(|mci| mci.ciphering_algorithm_scg_r12.as_ref());
        maybe_cipher.is_some_and(|cipher| cipher.0 == CipheringAlgorithm_r12::EEA0)
    }
}

impl Analyzer for NullCipherAnalyzer {
    fn get_name(&self) -> Cow<'_, str> {
        Cow::from("Null Cipher")
    }

    fn get_description(&self) -> Cow<'_, str> {
        Cow::from("Tests whether the cell suggests using a null cipher (EEA0)")
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
        let dcch_msg = match ie {
            InformationElement::LTE(lte_ie) => match &**lte_ie {
                LteInformationElement::DlDcch(dcch_msg) => dcch_msg,
                _ => return None,
            },
            _ => return None,
        };
        let null_cipher_detected = security_algorithm_configs(dcch_msg)
            .iter()
            .any(|config| config.ciphering_algorithm.0 == CipheringAlgorithm_r12::EEA0)
            || self.check_scg_cipher(dcch_msg);
        if null_cipher_detected {
            return Some(Event {
                event_type: EventType::High,
                message: "Cell suggested use of null cipher".to_string(),
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::util::test_messages::{
        nas_security_mode_command, rrc_handover_reconfiguration, rrc_security_mode_command,
    };

    fn analyze(ie: &InformationElement) -> Option<Event> {
        NullCipherAnalyzer {}.analyze_information_element(ie, 0, DateTime::default())
    }

    #[test]
    fn test_security_mode_command() {
        let event = analyze(&rrc_security_mode_command(0, 2)).expect("expected a warning");
        assert_eq!(event.event_type, EventType::High);
        assert!(analyze(&rrc_security_mode_command(2, 2)).is_none());
    }

    #[test]
    fn test_handover_reconfiguration() {
        let event = analyze(&rrc_handover_reconfiguration(0, 2)).expect("expected a warning");
        assert_eq!(event.event_type, EventType::High);
        assert!(analyze(&rrc_handover_reconfiguration(2, 2)).is_none());
    }

    #[test]
    fn test_ignores_nas() {
        assert!(analyze(&nas_security_mode_command(0, 2)).is_none());
    }
}
