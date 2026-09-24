//! Production crate root for the PRW remote bridge.
//!
//! Phase 152 C02e preserves the existing Phase 143 bridge implementation as a private submodule
//! and re-exports its public API while adding reviewed dynamic-reachability ownership, Tranche 5
//! freshness-token wire semantics, the Tranche 6 provider-neutral live-owner fencing seam, the
//! C02f-Y-selected asynchronous production live-owner authority port, the C02f-AC definitive
//! provider-outcome wrapper, the C02f-BS common acquisition sub-composition, and the C03e-X
//! already-authorized request dispatch helper. This root selection does not activate sockets, tasks,
//! networking, a concrete distributed tenancy backend or Agent bootstrap behavior.

#[path = "lib.rs"]
mod legacy_bridge;

pub use legacy_bridge::*;

pub mod authorized_request_dispatch;
pub mod candidate_publication_control_frame;
pub mod candidate_publication_execution;
pub mod candidate_publication_freshness;
pub mod candidate_publication_mesh_result_wire;
pub mod candidate_publication_result_wire;
pub mod candidate_publication_same_stream_response_custody;
pub mod candidate_publication_wire;
pub mod candidate_reachability;
pub mod capability_request_wire;
pub mod control_session_auth_wire;
pub mod post_auth_control_stream_ingress;
pub mod prwc_connection_authentication;
pub mod prwc_request_id_lifecycle;
pub mod reachability_durable_snapshot_codec;
pub mod reachability_durable_snapshot_etcd_store;
pub mod reachability_durable_snapshot_key_codec;
pub mod reachability_freshness_wire;
pub mod reachability_live_owner;
pub mod reachability_live_owner_acquisition_composition;
pub mod reachability_live_owner_async;
pub mod reachability_live_owner_currentness_execution;
pub mod reachability_live_owner_first_owner_acquisition;
// C02f-Y intentionally preserves the explicit `impl Future + Send` async authority contract.
#[allow(clippy::manual_async_fn)]
pub mod reachability_live_owner_provider_bridge;
pub mod reachability_live_owner_reconciled_acquisition;
pub mod reachability_live_owner_reconciled_acquisition_execution;
pub mod reachability_live_owner_reconciled_release;
pub mod reachability_live_owner_reconciled_release_execution;
pub mod reachability_owner;
pub mod remote_server_transport_runtime;
pub mod remote_session_binding;
pub mod requester_rendezvous_authority;
pub mod requester_rendezvous_dr_acknowledgement_wire;
pub mod requester_rendezvous_in_memory_provider;
pub mod requester_rendezvous_target_request_io;
pub mod requester_rendezvous_target_request_wire;
pub mod session_auth_wire;
