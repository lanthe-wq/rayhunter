//! Helpers shared between analyzers.

use telcom_parser::lte_rrc::{
    DL_DCCH_Message, DL_DCCH_MessageType, DL_DCCH_MessageType_c1,
    RRCConnectionReconfiguration_r8_IEs, RRCConnectionReconfiguration_v1250_IEs,
    RRCConnectionReconfigurationCriticalExtensions,
    RRCConnectionReconfigurationCriticalExtensions_c1, SecurityAlgorithmConfig,
    SecurityConfigHO_v1530HandoverType_v1530, SecurityConfigHOHandoverType,
    SecurityModeCommandCriticalExtensions, SecurityModeCommandCriticalExtensions_c1,
};

/// Returns the r8 IEs of an RRCConnectionReconfiguration message.
pub fn rrc_connection_reconfiguration_r8(
    msg: &DL_DCCH_Message,
) -> Option<&RRCConnectionReconfiguration_r8_IEs> {
    if let DL_DCCH_MessageType::C1(DL_DCCH_MessageType_c1::RrcConnectionReconfiguration(
        reconfiguration,
    )) = &msg.message
        && let RRCConnectionReconfigurationCriticalExtensions::C1(
            RRCConnectionReconfigurationCriticalExtensions_c1::RrcConnectionReconfiguration_r8(r8),
        ) = &reconfiguration.critical_extensions
    {
        return Some(r8);
    }
    None
}

/// Follows the chain of non-critical extensions of an RRCConnectionReconfiguration
/// down to its v1250 IEs.
pub fn rrc_connection_reconfiguration_v1250(
    r8: &RRCConnectionReconfiguration_r8_IEs,
) -> Option<&RRCConnectionReconfiguration_v1250_IEs> {
    r8.non_critical_extension
        .as_ref()
        .and_then(|v890| v890.non_critical_extension.as_ref())
        .and_then(|v920| v920.non_critical_extension.as_ref())
        .and_then(|v1020| v1020.non_critical_extension.as_ref())
        .and_then(|v1130| v1130.non_critical_extension.as_ref())
}

/// Returns every [SecurityAlgorithmConfig] a cell sends in a DL-DCCH message: the
/// one in a SecurityModeCommand, or those in the handover security configs of an
/// RRCConnectionReconfiguration.
pub fn security_algorithm_configs(msg: &DL_DCCH_Message) -> Vec<&SecurityAlgorithmConfig> {
    let mut configs = Vec::new();

    if let DL_DCCH_MessageType::C1(DL_DCCH_MessageType_c1::SecurityModeCommand(command)) =
        &msg.message
        && let SecurityModeCommandCriticalExtensions::C1(
            SecurityModeCommandCriticalExtensions_c1::SecurityModeCommand_r8(r8),
        ) = &command.critical_extensions
    {
        configs.push(&r8.security_config_smc.security_algorithm_config);
    }

    let Some(r8) = rrc_connection_reconfiguration_r8(msg) else {
        return configs;
    };
    if let Some(handover) = &r8.security_config_ho {
        match &handover.handover_type {
            SecurityConfigHOHandoverType::IntraLTE(lte) => {
                configs.extend(lte.security_algorithm_config.as_ref());
            }
            SecurityConfigHOHandoverType::InterRAT(rat) => {
                configs.push(&rat.security_algorithm_config);
            }
        }
    }

    let maybe_v1530_security_config = rrc_connection_reconfiguration_v1250(r8)
        .and_then(|v1250| v1250.non_critical_extension.as_ref())
        .and_then(|v1310| v1310.non_critical_extension.as_ref())
        .and_then(|v1430| v1430.non_critical_extension.as_ref())
        .and_then(|v1510| v1510.non_critical_extension.as_ref())
        .and_then(|v1530| v1530.security_config_ho_v1530.as_ref());
    if let Some(v1530_security_config) = maybe_v1530_security_config {
        match &v1530_security_config.handover_type_v1530 {
            SecurityConfigHO_v1530HandoverType_v1530::Intra5GC(intra_5gc) => {
                configs.extend(intra_5gc.security_algorithm_config_r15.as_ref());
            }
            SecurityConfigHO_v1530HandoverType_v1530::Fivegc_ToEPC(to_epc) => {
                configs.push(&to_epc.security_algorithm_config_r15);
            }
            SecurityConfigHO_v1530HandoverType_v1530::Epc_To5GC(to_5gc) => {
                configs.push(&to_5gc.security_algorithm_config_r15);
            }
        }
    }

    configs
}

/// Builders for the messages that carry security algorithm configs, for use in
/// analyzer tests.
#[cfg(test)]
pub(crate) mod test_messages {
    use telcom_parser::lte_rrc::{
        CipheringAlgorithm_r12, DL_DCCH_Message, DL_DCCH_MessageType, DL_DCCH_MessageType_c1,
        NextHopChainingCount, RRC_TransactionIdentifier, RRCConnectionReconfiguration,
        RRCConnectionReconfiguration_r8_IEs, RRCConnectionReconfigurationCriticalExtensions,
        RRCConnectionReconfigurationCriticalExtensions_c1, SecurityAlgorithmConfig,
        SecurityAlgorithmConfigIntegrityProtAlgorithm, SecurityConfigHO,
        SecurityConfigHOHandoverType, SecurityConfigHOHandoverType_intraLTE,
        SecurityConfigHOHandoverType_intraLTEKeyChangeIndicator,
    };

    use crate::analysis::information_element::{InformationElement, LteInformationElement};
    use crate::gsmtap::{GsmtapHeader, GsmtapMessage, GsmtapType, LteNasSubtype, LteRrcSubtype};

    /// An RRC SecurityModeCommand, decoded from its UPER encoding.
    pub fn rrc_security_mode_command(cipher: u8, integrity: u8) -> InformationElement {
        // DL-DCCH c1 choice (1 bit) + securityModeCommand (4 bits) + transaction id (2 bits)
        // + criticalExtensions c1 (1 bit) + securityModeCommand-r8 (2 bits) + no
        // nonCriticalExtension (1 bit) + SecurityConfigSMC extension marker (1 bit) are
        // 12 zero-valued bits apart from the choice index, so 0x30 and a 0 nibble. Each
        // algorithm then takes an extension marker and 3 bits.
        let payload = vec![0x30, cipher & 0x7, (integrity & 0x7) << 4];
        InformationElement::try_from(&GsmtapMessage {
            header: GsmtapHeader::new(GsmtapType::LteRrc(LteRrcSubtype::DlDcch)),
            payload,
        })
        .expect("failed to decode RRC security mode command")
    }

    /// An RRCConnectionReconfiguration carrying an intra-LTE handover security config.
    pub fn rrc_handover_reconfiguration(cipher: u8, integrity: u8) -> InformationElement {
        let r8 = RRCConnectionReconfiguration_r8_IEs {
            meas_config: None,
            mobility_control_info: None,
            dedicated_info_nas_list: None,
            radio_resource_config_dedicated: None,
            security_config_ho: Some(SecurityConfigHO {
                handover_type: SecurityConfigHOHandoverType::IntraLTE(
                    SecurityConfigHOHandoverType_intraLTE {
                        security_algorithm_config: Some(SecurityAlgorithmConfig {
                            ciphering_algorithm: CipheringAlgorithm_r12(cipher),
                            integrity_prot_algorithm: SecurityAlgorithmConfigIntegrityProtAlgorithm(
                                integrity,
                            ),
                        }),
                        key_change_indicator:
                            SecurityConfigHOHandoverType_intraLTEKeyChangeIndicator(false),
                        next_hop_chaining_count: NextHopChainingCount(0),
                    },
                ),
            }),
            non_critical_extension: None,
        };
        let msg = DL_DCCH_Message {
            message: DL_DCCH_MessageType::C1(
                DL_DCCH_MessageType_c1::RrcConnectionReconfiguration(
                    RRCConnectionReconfiguration {
                        rrc_transaction_identifier: RRC_TransactionIdentifier(0),
                        critical_extensions: RRCConnectionReconfigurationCriticalExtensions::C1(
                            RRCConnectionReconfigurationCriticalExtensions_c1::RrcConnectionReconfiguration_r8(r8),
                        ),
                    },
                ),
            ),
        };
        InformationElement::LTE(Box::new(LteInformationElement::DlDcch(Box::new(msg))))
    }

    /// A plain EMM NAS SecurityModeCommand.
    pub fn nas_security_mode_command(cipher: u8, integrity: u8) -> InformationElement {
        // EMM protocol discriminator, SecurityModeCommand message type, the selected
        // algorithms, the NAS key set identifier, and the replayed UE security capabilities.
        let payload = vec![
            0x07,
            0x5d,
            ((cipher & 0x7) << 4) | (integrity & 0x7),
            0x00,
            0x02,
            0xf0,
            0x70,
        ];
        InformationElement::try_from(&GsmtapMessage {
            header: GsmtapHeader::new(GsmtapType::LteNas(LteNasSubtype::Plain)),
            payload,
        })
        .expect("failed to decode NAS security mode command")
    }
}

#[cfg(test)]
mod tests {
    use super::test_messages::{rrc_handover_reconfiguration, rrc_security_mode_command};
    use super::*;
    use crate::analysis::information_element::{InformationElement, LteInformationElement};

    fn dl_dcch(ie: &InformationElement) -> &DL_DCCH_Message {
        match ie {
            InformationElement::LTE(lte_ie) => match &**lte_ie {
                LteInformationElement::DlDcch(msg) => msg,
                other => panic!("expected a DL-DCCH message, got {other:?}"),
            },
            other => panic!("expected an LTE message, got {other:?}"),
        }
    }

    fn algorithms(ie: &InformationElement) -> Vec<(u8, u8)> {
        security_algorithm_configs(dl_dcch(ie))
            .iter()
            .map(|config| {
                (
                    config.ciphering_algorithm.0,
                    config.integrity_prot_algorithm.0,
                )
            })
            .collect()
    }

    #[test]
    fn test_security_mode_command() {
        assert_eq!(algorithms(&rrc_security_mode_command(2, 1)), vec![(2, 1)]);
        assert_eq!(algorithms(&rrc_security_mode_command(0, 3)), vec![(0, 3)]);
    }

    #[test]
    fn test_handover_reconfiguration() {
        assert_eq!(
            algorithms(&rrc_handover_reconfiguration(1, 2)),
            vec![(1, 2)]
        );
    }
}
