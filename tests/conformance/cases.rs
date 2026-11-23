//! The conformance case list: every procedure the crate implements, each mapped to the tests
//! that cover it or to the reason it is uncovered.
//!
//! The case ids are this crate's own (`<area>-<procedure>`), and the procedures are summarised
//! in our own words from IEC 60870-5-101 and -104. The conformance test specifications, IEC TS
//! 60870-5-604 (104) and -601 (101), are not held yet, so the cases are *derived* from the
//! procedures rather than taken from the specifications' case lists, and `ts_id` stays empty
//! until they are; no case id of theirs is invented here.
//!
//! This module is plain data and one renderer, with no dependency, so anything that reports
//! coverage — `tests/conformance.rs`, a conformance-statement generator — includes it with
//! `#[path]` and reads the same list.

#![allow(dead_code)]

use std::fmt::Write as _;

/// Scope of the procedure. Independent evidence is tracked separately for each case.
pub enum Role {
    Codec,
    Controlling,
    Controlled,
    BothStations,
    PrimarySecondary,
    Secondary,
}

impl Role {
    fn label(&self) -> &'static str {
        match self {
            Self::Codec => "Role-independent codec",
            Self::Controlling => "Controlling station",
            Self::Controlled => "Controlled station",
            Self::BothStations => "Controlling and controlled stations",
            Self::PrimarySecondary => "Primary and secondary links",
            Self::Secondary => "Secondary link",
        }
    }
}

/// One conformance case.
pub struct Case {
    /// Our stable id, `<area>-<procedure>`.
    pub id: &'static str,
    /// The case id in IEC TS 60870-5-604/-601, once the specification is held.
    pub ts_id: Option<&'static str>,
    /// Protocol roles to which this project procedure applies.
    pub role: Role,
    /// What the case checks, in one line.
    pub procedure: &'static str,
    /// The tests that cover it.
    pub tests: &'static [TestRef],
    /// What is not covered, and why.
    pub gap: Option<Gap>,
}

/// A test function in a test target.
pub struct TestRef {
    /// The target's file stem under `tests/`.
    pub file: &'static str,
    /// A `#[test]` function in that file.
    pub name: &'static str,
}

/// What a case's tests leave uncovered.
pub struct Gap {
    /// Why.
    pub reason: Reason,
    /// What, in a few words.
    pub note: &'static str,
}

/// Why part of a case is uncovered.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Reason {
    /// Needs a real serial line, modem or RTU.
    Hardware,
    /// The rule is engineering judgement until the standard is held.
    StandardNotHeld,
    /// The procedure is not implemented yet.
    NotImplemented,
    /// No third-party peer exercises it in the interop harness yet.
    NoThirdParty,
}

impl Reason {
    /// The reason as the table shows it.
    pub fn label(self) -> &'static str {
        match self {
            Reason::Hardware => "needs hardware",
            Reason::StandardNotHeld => "standard not held",
            Reason::NotImplemented => "not implemented",
            Reason::NoThirdParty => "no third-party scenario",
        }
    }
}

/// The kind of evidence a test is, from its target's name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Evidence {
    /// A unit or integration test against this crate alone.
    Unit,
    /// A deterministic simulation under many seeds.
    Simulation,
    /// The replay of committed fuzz inputs.
    Fuzz,
    /// Wireshark's dissector.
    Oracle,
    /// lib60870-C, a second stack.
    Interop,
}

impl Evidence {
    /// Every kind, in table order.
    pub const ALL: [Evidence; 5] = [Evidence::Unit, Evidence::Simulation, Evidence::Fuzz, Evidence::Oracle, Evidence::Interop];

    /// The kind of evidence the target `file` is.
    pub fn of(file: &str) -> Evidence {
        if file.starts_with("interop") {
            Evidence::Interop
        } else if file.starts_with("tshark") {
            Evidence::Oracle
        } else if file.starts_with("regressions") {
            Evidence::Fuzz
        } else if file.ends_with("simulation") {
            Evidence::Simulation
        } else {
            Evidence::Unit
        }
    }

    /// The column heading.
    pub fn label(self) -> &'static str {
        match self {
            Evidence::Unit => "unit",
            Evidence::Simulation => "simulation",
            Evidence::Fuzz => "fuzz replay",
            Evidence::Oracle => "Wireshark",
            Evidence::Interop => "lib60870-C",
        }
    }
}

const fn t(file: &'static str, name: &'static str) -> TestRef {
    TestRef { file, name }
}

/// Every case, in table order.
pub const CASES: &[Case] = &[
    // --- The ASDU codec, shared by 101 and 104 -------------------------------------------------
    Case {
        id: "ASDU-TYPES",
        role: Role::Codec,
        ts_id: None,
        procedure: "every standard type identification encodes and decodes to itself",
        tests: &[
            t("asdu_edges", "type_identifications_are_the_standard_numbers"),
            t("asdu_roundtrip", "every_standard_type_round_trips_under_every_width_combination"),
            t("asdu_roundtrip", "every_typed_variant_names_a_distinct_type"),
            t("reference_capture", "every_asdu_in_the_reference_capture_round_trips"),
            t("tshark_oracle", "wireshark_dissects_every_104_type_as_what_was_put_in"),
        ],
        gap: None,
    },
    Case {
        id: "ASDU-COT",
        role: Role::Codec,
        ts_id: None,
        procedure: "cause of transmission values, P/N and T bits, originator address",
        tests: &[t("asdu_edges", "causes_of_transmission_are_the_standard_numbers"), t("asdu_edges", "cot_octet_layout")],
        gap: None,
    },
    Case {
        id: "ASDU-WIDTHS",
        role: Role::Codec,
        ts_id: None,
        procedure: "COT 1/2, common address 1/2 and IOA 1/2/3 octets as a profile",
        tests: &[
            t("asdu_roundtrip", "every_standard_type_round_trips_under_every_width_combination"),
            t("asdu_roundtrip", "untyped_types_round_trip_as_raw_under_every_width_combination"),
            t("asdu_edges", "profile_constants"),
            t("asdu_edges", "encode_refuses_what_the_profile_cannot_carry"),
            t("regressions", "the_derivation_reaches_every_width"),
        ],
        gap: None,
    },
    Case {
        id: "ASDU-ELEMENTS",
        role: Role::Codec,
        ts_id: None,
        procedure: "information elements over their full declared ranges (quality, NVA, SVA, float, BCR, CP24/CP56)",
        tests: &[
            t("asdu_edges", "element_lengths_match_the_reference_tables"),
            t("asdu_edges", "element_bit_layouts"),
            t("asdu_edges", "normalized_limits"),
            t("asdu_edges", "scaled_limits"),
            t("asdu_edges", "floats_nan_and_infinities_keep_their_bits"),
            t("asdu_edges", "cp56_out_of_range_and_flags_are_kept_as_received"),
            t("asdu_edges", "cp24_substituted_bit_survives"),
            t("asdu_edges", "packed_single_points_type_20"),
            t("asdu_edges", "bitstring32_is_little_endian"),
            t("asdu_edges", "test_bit_and_negative_confirmation"),
            t("asdu_edges", "test_command_pattern_and_gi_bytes"),
            t("tshark_oracle", "wireshark_dissects_every_104_type_as_what_was_put_in"),
        ],
        gap: None,
    },
    Case {
        id: "ASDU-VSQ",
        role: Role::Codec,
        ts_id: None,
        procedure: "variable structure qualifier: SQ 0 and 1, object count, address overflow",
        tests: &[
            t("asdu_edges", "sequence_form_writes_one_address"),
            t("asdu_edges", "vsq_overclaim_is_refused_at_the_first_missing_field"),
            t("asdu_edges", "sequence_address_overflow_is_refused"),
            t("asdu_edges", "zero_objects"),
        ],
        gap: None,
    },
    Case {
        id: "ASDU-MALFORMED",
        role: Role::Codec,
        ts_id: None,
        procedure: "truncated, over-long and malformed ASDUs are refused without panicking",
        tests: &[
            t("asdu_edges", "truncation_at_every_octet_names_the_field_and_its_offset"),
            t("asdu_edges", "trailing_octets_and_too_long_are_refused"),
            t("asdu_edges", "header_decodes_alone"),
            t("regressions", "every_committed_crash_input_replays_cleanly"),
        ],
        gap: None,
    },
    Case {
        id: "ASDU-UNKNOWN-TYPES",
        role: Role::Codec,
        ts_id: None,
        procedure: "private, reserved and security type identifications are kept as raw octets",
        tests: &[t("asdu_edges", "unknown_private_forbidden_and_security_types_decode_raw")],
        gap: None,
    },
    Case {
        id: "ASDU-PROFILE-TYPES",
        role: Role::Codec,
        ts_id: None,
        procedure: "a profile permits only the type identifications of its companion standard",
        tests: &[t("station_controlled", "test_command_104_and_delay_acquisition_work_where_the_profile_permits_them")],
        gap: Some(Gap { reason: Reason::StandardNotHeld, note: "the per-profile permission tables" }),
    },
    // --- The 104 link (APCI) ---------------------------------------------------------------------
    Case {
        id: "104-LINK-FORMATS",
        role: Role::BothStations,
        ts_id: None,
        procedure: "I, S and U formats, APDU length, malformed octets close the connection with a reason",
        tests: &[
            t("cs104_link", "malformed_octets_close_with_the_reason"),
            t("cs104_link", "unexpected_u_frames_close_with_their_name"),
            t("cs104_link", "partial_reads_of_one_octet_are_reassembled"),
            t("cs104_link", "submit_refuses_empty_and_too_long_asdus"),
            t("regressions_cs104", "every_committed_apci_input_replays_cleanly"),
            t("tshark_apci", "every_emitted_apci_frame_dissects_as_encoded"),
        ],
        gap: None,
    },
    Case {
        id: "104-LINK-STARTDT",
        role: Role::BothStations,
        ts_id: None,
        procedure: "STARTDT act/con; no I-frame before data transfer is started",
        tests: &[
            t("cs104_link", "an_i_frame_before_startdt_is_not_delivered_and_closes"),
            t("cs104_link", "submit_before_start_is_refused"),
            t("cs104_link", "only_the_controlling_role_starts_and_stops"),
            t("cs104_adapters", "start_and_exchange_in_both_directions"),
            t("interop", "server_startdt"),
            t("interop", "client_startdt"),
        ],
        gap: None,
    },
    Case {
        id: "104-LINK-STOPDT",
        role: Role::BothStations,
        ts_id: None,
        procedure: "STOPDT act/con, outstanding I-frames acknowledged before the confirmation",
        tests: &[
            t("cs104_link", "stopdt_act_with_outstanding_frames_withholds_the_con_until_they_are_acknowledged"),
            t("cs104_link", "stopdt_act_with_nothing_outstanding_is_confirmed_at_once_and_t1_still_bounds_a_drain"),
            t("cs104_link", "a_local_stop_acknowledges_and_still_accepts_in_flight_frames"),
            t("cs104_adapters", "stop_with_outstanding_frames_delivers_them_first"),
            t("interop", "server_stopdt_with_outstanding_frames"),
            t("interop", "client_stopdt_with_outstanding_frames"),
        ],
        gap: Some(Gap { reason: Reason::NoThirdParty, note: "the withheld confirmation against lib60870-C, whose master acknowledges before it stops" }),
    },
    Case {
        id: "104-LINK-TESTFR",
        role: Role::BothStations,
        ts_id: None,
        procedure: "TESTFR act/con after t3 idle, in every state and role",
        tests: &[
            t("cs104_link", "an_idle_link_sends_testfr_act_after_t3_and_closes_without_a_con"),
            t("cs104_link", "a_testfr_con_keeps_the_link_open_and_any_frame_restarts_t3"),
            t("cs104_link", "testfr_act_is_answered_in_every_state_and_role"),
            t("cs104_link", "an_unsolicited_testfr_con_is_ignored"),
            t("cs104_adapters", "testfr_keeps_an_idle_link_open"),
            t("interop", "server_t3_ours"),
            t("interop", "server_t3_theirs"),
            t("interop", "client_t3_ours"),
            t("interop", "client_t3_theirs"),
        ],
        gap: None,
    },
    Case {
        id: "104-LINK-K",
        role: Role::BothStations,
        ts_id: None,
        procedure: "at most k unacknowledged I-frames outstanding",
        tests: &[
            t("cs104_link", "k_outstanding_frames_refuse_the_next_submit_with_back_pressure"),
            t("cs104_adapters", "back_pressure_resolves_through_acknowledgments"),
            t("interop", "server_k_and_w_back_pressure"),
            t("interop", "client_k_and_w_back_pressure"),
        ],
        gap: None,
    },
    Case {
        id: "104-LINK-W",
        role: Role::BothStations,
        ts_id: None,
        procedure: "acknowledge at the latest after w received I-frames",
        tests: &[
            t("cs104_link", "w_received_frames_are_acknowledged_at_once"),
            t("cs104_link", "an_i_frame_sent_acknowledges_what_was_received"),
            t("interop", "server_k_and_w_back_pressure"),
            t("interop", "client_k_and_w_back_pressure"),
        ],
        gap: None,
    },
    Case {
        id: "104-LINK-T0",
        role: Role::Controlling,
        ts_id: None,
        procedure: "connection establishment gives up after t0",
        tests: &[t("cs104_adapters", "connect_gives_up_after_t0")],
        gap: Some(Gap { reason: Reason::NoThirdParty, note: "no lib60870-C scenario; a refused connection needs no peer" }),
    },
    Case {
        id: "104-LINK-T1",
        role: Role::BothStations,
        ts_id: None,
        procedure: "an unacknowledged I-frame or U act closes the connection after t1",
        tests: &[
            t("cs104_link", "an_unacknowledged_i_frame_closes_with_t1_expired_after_t1"),
            t("cs104_link", "t1_runs_on_the_oldest_outstanding_frame"),
            t("cs104_link", "t1_runs_on_startdt_act_and_stopdt_act"),
            t("cs104_adapters", "a_silent_peer_ends_in_t1_expired"),
            t("interop", "server_t1_expiry"),
            t("interop", "client_t1_expiry"),
        ],
        gap: None,
    },
    Case {
        id: "104-LINK-T2",
        role: Role::BothStations,
        ts_id: None,
        procedure: "fewer than w I-frames are acknowledged by an S-frame when t2 elapses",
        tests: &[
            t("cs104_link", "fewer_than_w_frames_are_acknowledged_when_t2_elapses"),
            t("interop", "server_t2_acknowledgment"),
            t("interop", "client_t2_acknowledgment"),
        ],
        gap: None,
    },
    Case {
        id: "104-LINK-SEQUENCE",
        role: Role::BothStations,
        ts_id: None,
        procedure: "send and receive sequence numbers: order, wrap at 32767, bad acknowledgments close",
        tests: &[
            t("cs104_link", "an_unexpected_send_sequence_number_closes"),
            t("cs104_link", "sequence_numbers_wrap_at_32767_in_both_directions"),
            t("cs104_link", "an_acknowledgment_of_a_frame_never_sent_closes"),
            t("cs104_link", "a_repeated_acknowledgment_is_harmless"),
            t("cs104_link", "a_peer_acknowledging_only_every_32767_frames_is_served"),
            t("simulation", "every_accepted_i_frame_is_delivered_once_in_order_or_the_connection_closes_with_a_reason"),
            t("regressions_cs104", "every_committed_link_input_replays_cleanly"),
        ],
        gap: None,
    },
    Case {
        id: "104-LINK-CLOSE",
        role: Role::BothStations,
        ts_id: None,
        procedure: "every close and disconnect is reported once with its reason",
        tests: &[
            t("cs104_link", "disconnect_and_close_name_their_reason_once"),
            t("cs104_adapters", "a_peer_close_is_reported_as_peer_closed"),
            t("simulation", "every_accepted_i_frame_is_delivered_once_in_order_or_the_connection_closes_with_a_reason"),
        ],
        gap: None,
    },
    Case {
        id: "104-LINK-CONFIG",
        role: Role::BothStations,
        ts_id: None,
        procedure: "k, w and t0-t3 are validated (w at most two thirds of k)",
        tests: &[t("cs104_link", "an_invalid_configuration_is_refused"), t("cs104_adapters", "an_invalid_configuration_and_an_unreachable_peer_are_errors")],
        gap: Some(Gap { reason: Reason::StandardNotHeld, note: "the defaults and ranges are taken from the peers" }),
    },
    // --- The stations, over 104 ----------------------------------------------------------------
    Case {
        id: "STA-GI",
        role: Role::BothStations,
        ts_id: None,
        procedure: "station interrogation: confirmation, the points (COT 20), termination",
        tests: &[
            t("station_controlled", "station_interrogation_answers_from_current_state"),
            t("station_controlled", "broadcast_gi_answers_every_common_address"),
            t("station_controlled", "large_interrogations_are_packed_up_to_the_maximum_length"),
            t("station_controlled", "a_gi_while_a_gi_is_in_progress_is_refused"),
            t("station_controlling", "gi_confirmed_answered_and_terminated_completes"),
            t("station_controlling", "gi_without_termination_times_out_naming_the_termination"),
            t("tshark_station", "every_station_apdu_dissects_as_decoded"),
            t("interop_station", "lib60870_client_runs_every_procedure_against_our_server"),
            t("interop_station", "our_client_runs_every_procedure_against_lib60870_server"),
        ],
        gap: None,
    },
    Case {
        id: "STA-GROUP-GI",
        role: Role::BothStations,
        ts_id: None,
        procedure: "group interrogation 1-16 answers only the group; an empty group only confirms",
        tests: &[
            t("station_controlled", "group_interrogation_answers_only_the_group_and_an_empty_group_only_confirms"),
            t("station_controlled", "a_bad_qualifier_or_ioa_is_refused"),
            t("interop_station", "lib60870_client_runs_every_procedure_against_our_server"),
            t("interop_station", "our_client_runs_every_procedure_against_lib60870_server"),
        ],
        gap: None,
    },
    Case {
        id: "STA-COUNTER",
        role: Role::BothStations,
        ts_id: None,
        procedure: "counter interrogation: read, freeze, reset",
        tests: &[
            t("station_controlled", "counter_interrogation_reads_freezes_and_resets"),
            t("station_controlling", "counter_interrogation_completes_on_termination"),
            t("interop_station", "lib60870_client_runs_every_procedure_against_our_server"),
            t("interop_station", "our_client_runs_every_procedure_against_lib60870_server"),
        ],
        gap: Some(Gap { reason: Reason::StandardNotHeld, note: "the counter interrogation modes" }),
    },
    Case {
        id: "STA-READ",
        role: Role::BothStations,
        ts_id: None,
        procedure: "read command answered with the current value (COT 5) or COT 47",
        tests: &[
            t("station_controlled", "read_answers_with_the_current_value_or_cot_47"),
            t("station_controlling", "read_completes_with_the_point"),
            t("interop_station", "lib60870_client_runs_every_procedure_against_our_server"),
            t("interop_station", "our_client_runs_every_procedure_against_lib60870_server"),
        ],
        gap: None,
    },
    Case {
        id: "STA-CLOCK",
        role: Role::BothStations,
        ts_id: None,
        procedure: "clock synchronisation, applied to later time tags; a refusal is negative",
        tests: &[
            t("station_controlled", "clock_sync_is_handed_to_the_handler_and_applied_to_later_time_tags"),
            t("station_controlled", "a_refused_clock_sync_is_negative_and_changes_nothing"),
            t("station_controlling", "clock_sync_carries_the_clock_time"),
            t("interop_station", "lib60870_client_runs_every_procedure_against_our_server"),
            t("interop_station", "our_client_runs_every_procedure_against_lib60870_server"),
        ],
        gap: None,
    },
    Case {
        id: "STA-TEST-COMMAND",
        role: Role::BothStations,
        ts_id: None,
        procedure: "test command (107 on 104, 104 where the profile permits it) mirrored",
        tests: &[
            t("station_controlled", "test_command_107_is_mirrored"),
            t("station_controlled", "test_command_104_and_delay_acquisition_work_where_the_profile_permits_them"),
            t("station_controlling", "test_command_is_107_on_104"),
            t("interop_station", "lib60870_client_runs_every_procedure_against_our_server"),
            t("interop_station", "our_client_runs_every_procedure_against_lib60870_server"),
        ],
        gap: None,
    },
    Case {
        id: "STA-RESET-PROCESS",
        role: Role::BothStations,
        ts_id: None,
        procedure: "reset process command; QRP 2 clears the event buffer",
        tests: &[
            t("station_controlled", "reset_process_asks_the_handler_and_qrp_2_clears_the_event_buffer"),
            t("station_controlled", "reset_process_qrp_2_drops_unsent_events"),
            t("station_controlling", "reset_process_and_parameters"),
            t("interop_station", "lib60870_client_runs_every_procedure_against_our_server"),
        ],
        gap: Some(Gap { reason: Reason::NoThirdParty, note: "our controlling station against lib60870-C's" }),
    },
    Case {
        id: "STA-PARAMETERS",
        role: Role::BothStations,
        ts_id: None,
        procedure: "parameter loading (110-112) and activation (113)",
        tests: &[t("station_controlled", "parameters_are_handed_to_the_handler_and_confirmed"), t("station_controlling", "reset_process_and_parameters")],
        gap: Some(Gap { reason: Reason::NoThirdParty, note: "neither role against lib60870-C" }),
    },
    Case {
        id: "STA-COMMAND-DIRECT",
        role: Role::BothStations,
        ts_id: None,
        procedure: "direct commands of every type (45-51, 58-64): confirmation and termination",
        tests: &[
            t("station_controlled", "direct_points_execute_directly_and_refuse_a_select"),
            t("station_controlled", "direct_or_select_points_take_both"),
            t("station_controlled", "bitstring_commands_are_direct"),
            t("station_controlled", "every_handler_call_carries_its_context"),
            t("station_controlling", "direct_commands_with_and_without_termination"),
            t("interop_station", "lib60870_client_runs_every_procedure_against_our_server"),
            t("interop_station", "our_client_runs_every_procedure_against_lib60870_server"),
        ],
        gap: None,
    },
    Case {
        id: "STA-COMMAND-SBO",
        role: Role::BothStations,
        ts_id: None,
        procedure: "select-before-operate: select, execute, confirmation and termination",
        tests: &[
            t("station_controlled", "select_then_execute_confirms_and_terminates"),
            t("station_controlling", "sbo_reports_selected_confirmed_completed"),
            t("station_controlling", "a_refused_select_sends_no_execute"),
            t("interop_station", "lib60870_client_runs_every_procedure_against_our_server"),
            t("interop_station", "our_client_runs_every_procedure_against_lib60870_server"),
        ],
        gap: None,
    },
    Case {
        id: "STA-COMMAND-SBO-REFUSAL",
        role: Role::Controlled,
        ts_id: None,
        procedure: "an execute without a matching, timely select from the same connection is refused and not executed",
        tests: &[
            t("station_controlled", "execute_without_select_is_refused_and_the_handler_is_not_called"),
            t("station_controlled", "an_execute_after_the_select_timeout_is_refused"),
            t("station_controlled", "an_execute_that_does_not_match_the_select_is_refused"),
            t("station_controlled", "an_execute_from_another_connection_is_refused"),
            t("station_controlled", "a_second_select_by_another_originator_is_refused_but_the_same_one_reselects"),
            t("station_controlled", "deactivation_cancels_a_select"),
            t("interop_station", "lib60870_client_runs_every_procedure_against_our_server"),
        ],
        gap: None,
    },
    Case {
        id: "STA-COMMAND-TIME-TAG",
        role: Role::Controlled,
        ts_id: None,
        procedure: "time-tagged commands (58-64) carry their CP56Time2a to the handler",
        tests: &[
            t("station_controlled", "time_tagged_commands_pass_their_time_to_the_handler"),
            t("interop_station", "lib60870_client_runs_every_procedure_against_our_server"),
        ],
        gap: Some(Gap { reason: Reason::StandardNotHeld, note: "the validity window of a time-tagged command" }),
    },
    Case {
        id: "STA-COMMAND-PENDING",
        role: Role::Controlled,
        ts_id: None,
        procedure: "a long-running command is confirmed now and terminated later",
        tests: &[],
        gap: Some(Gap { reason: Reason::NotImplemented, note: "a deferred activation termination" }),
    },
    Case {
        id: "STA-NEGATIVE",
        role: Role::BothStations,
        ts_id: None,
        procedure: "unknown type, cause, common address and IOA (COT 44-47) and refused commands are confirmed negatively",
        tests: &[
            t("station_controlled", "unknown_type_is_cot_44"),
            t("station_controlled", "unknown_cause_is_cot_45"),
            t("station_controlled", "unknown_common_address_is_cot_46"),
            t("station_controlled", "unknown_ioa_is_cot_47"),
            t("station_controlled", "a_refused_command_is_confirmed_negatively_without_termination"),
            t("station_controlled", "a_command_with_two_objects_is_refused"),
            t("station_controlled", "an_asdu_that_does_not_decode_is_dropped_and_counted"),
            t("station_controlling", "a_negative_confirmation_is_an_error_carrying_the_cot"),
            t("station_controlling", "cot_44_to_47_mirrors_are_negative"),
            t("interop_station", "lib60870_client_runs_every_procedure_against_our_server"),
            t("interop_station", "our_client_runs_every_procedure_against_lib60870_server"),
        ],
        gap: None,
    },
    Case {
        id: "STA-END-OF-INIT",
        role: Role::BothStations,
        ts_id: None,
        procedure: "end of initialisation (70) is the first ASDU after start",
        tests: &[
            t("station_controlled", "end_of_initialisation_comes_first_after_start"),
            t("station_controlling", "spontaneous_data_and_end_of_initialisation_are_events"),
        ],
        gap: Some(Gap { reason: Reason::NoThirdParty, note: "not asserted against lib60870-C" }),
    },
    Case {
        id: "STA-SPONTANEOUS",
        role: Role::BothStations,
        ts_id: None,
        procedure: "spontaneous events (COT 3) with the clock's time tag, packed by type",
        tests: &[
            t("station_controlled", "spontaneous_events_carry_the_clock_time_in_the_configured_format"),
            t("station_controlled", "events_are_packed_by_type_up_to_the_maximum_length"),
            t("station_controlling", "spontaneous_data_and_end_of_initialisation_are_events"),
            t("tshark_station", "every_station_apdu_dissects_as_decoded"),
            t("interop_station", "our_client_runs_every_procedure_against_lib60870_server"),
        ],
        gap: Some(Gap { reason: Reason::NoThirdParty, note: "our controlled station's events into lib60870-C's client" }),
    },
    Case {
        id: "STA-CYCLIC",
        role: Role::Controlled,
        ts_id: None,
        procedure: "cyclic (COT 1) and background (COT 2) transmission",
        tests: &[t("station_controlled", "cyclic_and_background_points_are_sent_periodically")],
        gap: Some(Gap { reason: Reason::NoThirdParty, note: "not exercised against lib60870-C" }),
    },
    Case {
        id: "STA-EVENT-BUFFER",
        role: Role::Controlled,
        ts_id: None,
        procedure: "events kept until acknowledged and re-sent after a reconnection or STOPDT; overflow reported",
        tests: &[
            t("station_controlled", "events_are_kept_until_acknowledged_and_re_sent_after_reconnection"),
            t("station_controlled", "an_update_storm_beyond_the_buffer_reports_the_loss_and_keeps_the_newest"),
            t("station_controlled", "stopdt_keeps_the_events_for_the_next_start"),
            t("station_adapters", "events_survive_a_reconnection_through_the_adapters"),
            t("station_simulation", "reconnect_delivers_every_event_or_reports_it_lost"),
            t("regressions_station", "every_committed_controlled_station_input_replays_cleanly"),
            t("interop_station", "our_client_runs_every_procedure_against_lib60870_server"),
        ],
        gap: Some(Gap { reason: Reason::NoThirdParty, note: "a connection dropped with events outstanding, against lib60870-C" }),
    },
    Case {
        id: "STA-REDUNDANCY",
        role: Role::Controlled,
        ts_id: None,
        procedure: "redundancy groups: one active connection, switch-over re-sends what was not acknowledged",
        tests: &[
            t("station_controlled", "a_switch_over_closes_the_old_connection_and_re_sends_its_unacknowledged_events_first"),
            t("station_controlled", "the_standby_connection_is_not_acted_on"),
            t("station_controlled", "groups_have_separate_buffers"),
            t("station_adapters", "a_redundancy_group_by_address_switches_over"),
            t("station_simulation", "switch_over_loses_nothing_and_duplicates_only_unacknowledged_events"),
        ],
        gap: Some(Gap { reason: Reason::StandardNotHeld, note: "the redundancy rule; no lib60870-C scenario" }),
    },
    Case {
        id: "STA-REQUESTS",
        role: Role::Controlling,
        ts_id: None,
        procedure: "the controlling station's requests: one per kind and address, timeouts, refused before start, failed on disconnect",
        tests: &[
            t("station_controlling", "no_confirmation_times_out_naming_the_confirmation"),
            t("station_controlling", "a_duplicate_request_is_busy_and_nothing_goes_before_start"),
            t("station_controlling", "a_disconnect_fails_every_outstanding_request"),
            t("station_controlling", "requests_wait_while_the_window_is_full"),
            t("station_controlling", "an_unstarted_master_refuses_requests"),
        ],
        gap: None,
    },
    Case {
        id: "STA-ADAPTERS",
        role: Role::BothStations,
        ts_id: None,
        procedure: "the blocking and Tokio client and server against each other",
        tests: &[
            t("station_adapters", "blocking_client_against_blocking_server"),
            t("station_adapters", "blocking_client_against_async_server"),
            t("station_adapters", "async_client_against_both_servers"),
        ],
        gap: None,
    },
    Case {
        id: "STA-FILE-TRANSFER",
        role: Role::BothStations,
        ts_id: None,
        procedure: "file retrieval (120-126): directory, select, call, segments, acknowledgments",
        tests: &[
            t("tshark_station", "every_station_apdu_dissects_as_decoded"),
            t("interop_station", "lib60870_client_runs_every_procedure_against_our_server"),
            t("file_transfer", "cancelled_downloads_late_reply_cannot_supply_successor_contents"),
            t("file_transfer", "cancel_download_targets_one_request_and_uses_resolved_name"),
            t("file_transfer", "dropping_download_future_deactivates_selected_file"),
            t("file_transfer", "timeout_deactivates_and_retry_waits_for_ordered_confirmation"),
            t("file_transfer", "download_is_byte_exact_across_sections_and_profiles"),
            t("file_transfer", "download_rejects_oversized_file_before_calling_it"),
            t("file_transfer", "checksum_failure_retries_only_the_bad_section_and_rejects_a_bad_file"),
            t("file_transfer", "interrupted_client_drops_partial_download"),
            t("file_transfer", "file_ready_rejects_oversize_and_completion_reports_the_file_identity"),
            t("file_transfer", "section_overrun_fails_before_returning_data"),
            t("file_transfer", "selection_is_connection_scoped_and_released_on_timeout_and_disconnect"),
            t("interop_station", "our_client_runs_every_procedure_against_lib60870_server"),
            t("file_directory", "directory_frames_fit_both_profiles_and_only_the_last_entry_ends_the_listing"),
            t("file_directory", "blocking_client_collects_complete_empty_and_unknown_directories"),
            t("file_directory", "async_client_collects_directory_from_async_server"),
            t("file_directory", "server_refuses_oversized_catalogs_and_unrepresentable_records"),
            t("file_directory", "malformed_end_marker_fails_request_and_releases_it"),
            t("file_directory", "oversized_directory_is_refused_before_any_partial_listing_is_returned"),
            t("file_directory", "incomplete_directory_times_out_and_another_station_cannot_finish_it"),
        ],
        gap: None,
    },
    // --- The 101 link (FT 1.2) -----------------------------------------------------------------
    Case {
        id: "101-LINK-FRAMES",
        role: Role::Codec,
        ts_id: None,
        procedure: "FT 1.2 single character, fixed and variable frames; bad checksum, end or length discarded",
        tests: &[
            t("cs101_link", "bad_checksum_end_and_length_are_discarded_and_counted"),
            t("cs101_link", "an_interrupted_frame_is_discarded"),
            t("cs101_link", "single_char_e5_is_ack_and_no_data"),
            t("regressions_cs101", "every_committed_ft12_input_replays_cleanly"),
            t("tshark_ft12", "every_emitted_frame_dissects_as_what_was_put_in"),
        ],
        gap: None,
    },
    Case {
        id: "101-LINK-ADDRESS",
        role: Role::PrimarySecondary,
        ts_id: None,
        procedure: "link address of 0, 1 or 2 octets; a foreign address is ignored",
        tests: &[
            t("cs101_link", "every_address_width_works_end_to_end"),
            t("cs101_link", "foreign_address_is_ignored"),
            t("cs101_link", "constructors_check_addresses"),
            t("interop_cs101", "unbalanced_primary_against_lib60870_slave"),
            t("interop_cs101", "unbalanced_primary_against_lib60870_slave_two_octet_address"),
            t("interop_cs101", "passive_cli_decodes_independent_master_link_status"),
        ],
        gap: None,
    },
    Case {
        id: "101-LINK-BROADCAST",
        role: Role::Secondary,
        ts_id: None,
        procedure: "a broadcast is delivered and never answered",
        tests: &[t("cs101_link", "broadcast_is_delivered_and_never_answered")],
        gap: Some(Gap { reason: Reason::NoThirdParty, note: "not exercised against lib60870-C" }),
    },
    Case {
        id: "101-LINK-UNBALANCED-POLL",
        role: Role::PrimarySecondary,
        ts_id: None,
        procedure: "unbalanced polling of class 1 and class 2, ACD, several secondaries round-robin",
        tests: &[
            t("cs101_link", "class2_poll_with_class1_pending_sets_acd_and_master_polls_class1"),
            t("cs101_link", "end_to_end_class1_and_class2_arrive_and_are_acknowledged"),
            t("cs101_link", "two_outstations_are_polled_round_robin"),
            t("cs101_station", "stations_over_an_unbalanced_link"),
            t("cs101_adapters", "unbalanced_over_tcp"),
            t("interop_cs101", "unbalanced_primary_against_lib60870_slave"),
            t("interop_cs101", "unbalanced_secondary_against_lib60870_master"),
        ],
        gap: None,
    },
    Case {
        id: "101-LINK-FCB",
        role: Role::PrimarySecondary,
        ts_id: None,
        procedure: "frame count bit: a repeated FCB gets the identical response, user data delivered once",
        tests: &[
            t("cs101_link", "repeated_fcb_gets_the_identical_response_and_nothing_is_dequeued"),
            t("cs101_link", "repeated_user_data_is_acknowledged_but_delivered_once"),
            t("cs101_link", "master_retransmits_byte_identical_frame_after_timeout"),
            t("cs101_link", "fcv_frame_before_reset_is_answered_not_functioning"),
            t("cs101_simulation", "every_asdu_is_delivered_at_most_once_and_ends_named"),
            t("interop_cs101", "unbalanced_secondary_against_lib60870_master"),
        ],
        gap: None,
    },
    Case {
        id: "101-LINK-RESET-AND-RETRIES",
        role: Role::PrimarySecondary,
        ts_id: None,
        procedure: "link reset, bounded retries, a silent secondary stopped without stalling the others",
        tests: &[
            t("cs101_link", "a_silent_outstation_is_stopped_and_does_not_stall_the_other"),
            t("cs101_link", "retries_exhausted_reports_user_data_unconfirmed"),
            t("cs101_link", "reset_with_a_response_in_flight_reports_it_unconfirmed"),
            t("cs101_link", "disconnect_and_close_end_the_link"),
            t("regressions_cs101", "every_committed_link_input_replays_cleanly"),
        ],
        gap: None,
    },
    Case {
        id: "101-LINK-DFC",
        role: Role::PrimarySecondary,
        ts_id: None,
        procedure: "data flow control: a busy secondary sets DFC and the primary holds user data",
        tests: &[t("cs101_link", "busy_secondary_sets_dfc_and_the_master_holds_user_data")],
        gap: Some(Gap { reason: Reason::NoThirdParty, note: "not exercised against lib60870-C" }),
    },
    Case {
        id: "101-LINK-BALANCED",
        role: Role::PrimarySecondary,
        ts_id: None,
        procedure: "balanced transmission in both directions with DIR, test function when idle",
        tests: &[
            t("cs101_link", "balanced_runs_both_directions_with_dir"),
            t("cs101_link", "balanced_sends_test_function_when_idle"),
            t("cs101_station", "stations_over_a_balanced_link"),
            t("cs101_adapters", "balanced_over_tcp"),
            t("interop_cs101", "balanced_controlled_against_lib60870_master"),
            t("interop_cs101", "balanced_controlling_against_lib60870_slave"),
        ],
        gap: None,
    },
    Case {
        id: "101-LINK-FUNCTIONS",
        role: Role::Secondary,
        ts_id: None,
        procedure: "reserved and unsupported function codes are answered as not implemented",
        tests: &[t("cs101_link", "reserved_and_unsupported_functions_are_not_implemented"), t("cs101_link", "submit_refusals_are_named")],
        gap: None,
    },
    Case {
        id: "101-LINK-TIMING",
        role: Role::PrimarySecondary,
        ts_id: None,
        procedure: "inter-character timeout and line idle detection",
        tests: &[
            t("cs101_link", "an_interrupted_frame_is_discarded"),
            t("cs101_link", "deadlines_are_reported"),
            t("cs101_simulation", "every_asdu_is_delivered_at_most_once_and_ends_named"),
        ],
        gap: Some(Gap { reason: Reason::Hardware, note: "a real line, UART and modem timing" }),
    },
    Case {
        id: "101-LINK-SERIAL",
        role: Role::PrimarySecondary,
        ts_id: None,
        procedure: "the serial adapter over a serial device",
        tests: &[
            t("cs101_adapters", "unbalanced_over_a_pty_pair"),
            t("cs101_adapters", "balanced_over_a_pty_pair"),
            t("cs101_adapters", "open_serial_reports_a_missing_port"),
            t("cs101_adapters", "unbalanced_under_tokio"),
        ],
        gap: Some(Gap { reason: Reason::Hardware, note: "a USB-RS-485/RS-232 adapter and a real 101 outstation" }),
    },
    Case {
        id: "101-STA-PROCEDURES",
        role: Role::BothStations,
        ts_id: None,
        procedure: "the station procedures over a 101 link",
        tests: &[t("cs101_station", "stations_over_an_unbalanced_link"), t("cs101_station", "stations_over_a_balanced_link")],
        gap: Some(Gap { reason: Reason::NoThirdParty, note: "the station procedures against lib60870-C over 101, and a real outstation" }),
    },
    // --- Security --------------------------------------------------------------------------------
    Case {
        id: "SEC-TLS",
        role: Role::BothStations,
        ts_id: None,
        procedure: "IEC 62351-3 TLS for 104 with mutual authentication",
        tests: &[t("tls", "a_client_without_a_certificate_is_refused_before_startdt"), t("interop_tls", "mutual_tls_with_lib60870_in_both_roles")],
        gap: None,
    },
    Case {
        id: "SEC-AUTHENTICATION",
        role: Role::BothStations,
        ts_id: None,
        procedure: "IEC 62351-5 authentication of critical ASDUs",
        tests: &[],
        gap: Some(Gap { reason: Reason::NotImplemented, note: "secure authentication" }),
    },
];

/// Counts for the summary line.
pub struct Summary {
    /// Cases in the list.
    pub cases: usize,
    /// Cases with tests and no gap.
    pub covered: usize,
    /// Cases with tests and a gap.
    pub partial: usize,
    /// Cases with no test.
    pub uncovered: usize,
    /// Cases with at least one lib60870-C test.
    pub interop: usize,
    /// Gaps by reason.
    pub by_reason: Vec<(Reason, usize)>,
}

/// The summary of `cases`.
pub fn summary(cases: &[Case]) -> Summary {
    let mut by_reason: Vec<(Reason, usize)> = Vec::new();
    for g in cases.iter().filter_map(|c| c.gap.as_ref()) {
        match by_reason.iter_mut().find(|(r, _)| *r == g.reason) {
            Some((_, n)) => *n += 1,
            None => by_reason.push((g.reason, 1)),
        }
    }
    by_reason.sort();
    Summary {
        cases: cases.len(),
        covered: cases.iter().filter(|c| !c.tests.is_empty() && c.gap.is_none()).count(),
        partial: cases.iter().filter(|c| !c.tests.is_empty() && c.gap.is_some()).count(),
        uncovered: cases.iter().filter(|c| c.tests.is_empty()).count(),
        interop: cases.iter().filter(|c| c.tests.iter().any(|r| Evidence::of(r.file) == Evidence::Interop)).count(),
        by_reason,
    }
}

/// The coverage table as Markdown.
pub fn markdown(cases: &[Case]) -> String {
    let s = summary(cases);
    let mut out = String::new();
    out.push_str("# Conformance coverage\n\n");
    out.push_str(
        "Generated by `cargo test --test conformance` from `tests/conformance/cases.rs`. The case ids are this \
         crate's own, derived from the procedures of IEC 60870-5-101 and -104; the column for the IEC TS \
         60870-5-604/-601 case id is filled once those specifications are held.\n\n",
    );
    let reasons: Vec<String> = s.by_reason.iter().map(|(r, n)| format!("{} {n}", r.label())).collect();
    let _ = writeln!(
        out,
        "{} cases: {} covered, {} covered with a gap, {} uncovered; {} with lib60870-C interop. Gaps: {}.\n",
        s.cases,
        s.covered,
        s.partial,
        s.uncovered,
        s.interop,
        reasons.join(", ")
    );
    out.push_str("| Case | TS id | Role | Procedure |");
    for e in Evidence::ALL {
        let _ = write!(out, " {} |", e.label());
    }
    out.push_str(" Gap |\n|---|---|---|---|");
    for _ in Evidence::ALL {
        out.push_str("---|");
    }
    out.push_str("---|\n");
    for case in cases {
        let _ = write!(out, "| `{}` | {} | {} | {} |", case.id, case.ts_id.unwrap_or("—"), case.role.label(), case.procedure);
        for e in Evidence::ALL {
            let names: Vec<String> = case.tests.iter().filter(|r| Evidence::of(r.file) == e).map(|r| format!("`{}::{}`", r.file, r.name)).collect();
            let _ = write!(out, " {} |", if names.is_empty() { "—".to_string() } else { names.join("<br>") });
        }
        match &case.gap {
            Some(g) => {
                let _ = writeln!(out, " {}: {} |", g.reason.label(), g.note);
            }
            None => out.push_str(" — |\n"),
        }
    }
    out
}
