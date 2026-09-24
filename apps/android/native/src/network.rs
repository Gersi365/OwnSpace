use std::net::{IpAddr, Ipv4Addr};

use jni::{
    EnvUnowned,
    errors::ThrowRuntimeExAndDefault,
    objects::{JByteArray, JClass},
    sys::{jboolean, jint, jlong},
};
use prw_connectivity::{
    CandidateId, ConnectivityCandidate, ConnectivityEndpoint, ConnectivityPathKind,
    PeerConnectivityIdentity, PeerConnectivityPlan, ReachabilityObservation,
    SelectedConnectivityPath, TransportIdentity,
};
use prw_core::DeviceId;
use prw_forwarding::{ForwardTarget, LoopbackBind, LoopbackFamily, PortForwardId, TcpForwardSpec};
use prw_private_dns::{DnsDomainSuffix, PrivateDnsConfig, PrivateDnsMode, ResolverEndpoint};
use prw_remote_bridge::BridgeCommand;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkAdapterError {
    Identifier,
    Family,
    Port,
    Address,
    Bridge,
    Observation,
    Connectivity,
    Dns,
    Utf8,
}

fn utf8(input: &[u8]) -> Result<&str, NetworkAdapterError> {
    std::str::from_utf8(input).map_err(|_| NetworkAdapterError::Utf8)
}

fn forward_id(value: i64) -> Result<PortForwardId, NetworkAdapterError> {
    let value = u64::try_from(value).map_err(|_| NetworkAdapterError::Identifier)?;
    PortForwardId::new(value).map_err(|_| NetworkAdapterError::Identifier)
}

const fn family(value: i32) -> Result<LoopbackFamily, NetworkAdapterError> {
    match value {
        0 => Ok(LoopbackFamily::Ipv4),
        1 => Ok(LoopbackFamily::Ipv6),
        _ => Err(NetworkAdapterError::Family),
    }
}

fn port(value: i32) -> Result<u16, NetworkAdapterError> {
    u16::try_from(value).map_err(|_| NetworkAdapterError::Port)
}

fn target(input: &[u8], target_port: i32) -> Result<ForwardTarget, NetworkAdapterError> {
    let address = utf8(input)?
        .parse::<IpAddr>()
        .map_err(|_| NetworkAdapterError::Address)?;
    ForwardTarget::new(address, port(target_port)?).map_err(|_| NetworkAdapterError::Address)
}

fn encode_forward_open(
    id: i64,
    family_code: i32,
    bind_port: i32,
    target_address: &[u8],
    target_port: i32,
) -> Result<Vec<u8>, NetworkAdapterError> {
    let bind = LoopbackBind::new(family(family_code)?, port(bind_port)?)
        .map_err(|_| NetworkAdapterError::Port)?;
    let spec = TcpForwardSpec::new(bind, target(target_address, target_port)?);
    BridgeCommand::ForwardOpen {
        forward_id: forward_id(id)?,
        spec,
    }
    .encode()
    .map_err(|_| NetworkAdapterError::Bridge)
}

fn encode_forward_close(id: i64) -> Result<Vec<u8>, NetworkAdapterError> {
    BridgeCommand::ForwardClose(forward_id(id)?)
        .encode()
        .map_err(|_| NetworkAdapterError::Bridge)
}

fn is_forward_payload(payload: &[u8]) -> bool {
    matches!(
        BridgeCommand::decode(payload),
        Ok(BridgeCommand::ForwardOpen { .. } | BridgeCommand::ForwardClose(_))
    )
}

const fn observation(value: i32) -> Result<ReachabilityObservation, NetworkAdapterError> {
    match value {
        0 => Ok(ReachabilityObservation::Unknown),
        1 => Ok(ReachabilityObservation::Reachable),
        2 => Ok(ReachabilityObservation::Unreachable),
        _ => Err(NetworkAdapterError::Observation),
    }
}

fn connectivity_candidate(
    id: u64,
    kind: ConnectivityPathKind,
    port: u16,
) -> Result<ConnectivityCandidate, NetworkAdapterError> {
    let id = CandidateId::new(id).map_err(|_| NetworkAdapterError::Connectivity)?;
    let endpoint = ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
        .map_err(|_| NetworkAdapterError::Connectivity)?;
    Ok(ConnectivityCandidate::new(id, kind, endpoint))
}

fn selected_path_code(local: i32, internet: i32, relay: i32) -> Result<i32, NetworkAdapterError> {
    let peer = PeerConnectivityIdentity::new(
        DeviceId::new("phase149-android-disposable")
            .map_err(|_| NetworkAdapterError::Connectivity)?,
        TransportIdentity::new([149; 32]).map_err(|_| NetworkAdapterError::Connectivity)?,
    );
    let candidates = vec![
        connectivity_candidate(1, ConnectivityPathKind::LocalDirect, 24_901)?,
        connectivity_candidate(2, ConnectivityPathKind::InternetDirect, 24_902)?,
        connectivity_candidate(3, ConnectivityPathKind::Relay, 24_903)?,
    ];
    let mut plan = PeerConnectivityPlan::new(peer, candidates)
        .map_err(|_| NetworkAdapterError::Connectivity)?;
    for (id, value) in [(1, local), (2, internet), (3, relay)] {
        plan.set_observation(
            CandidateId::new(id).map_err(|_| NetworkAdapterError::Connectivity)?,
            observation(value)?,
        )
        .map_err(|_| NetworkAdapterError::Connectivity)?;
    }
    Ok(match plan.selected_path() {
        SelectedConnectivityPath::Offline => 0,
        SelectedConnectivityPath::Candidate(candidate) => match candidate.kind() {
            ConnectivityPathKind::LocalDirect => 1,
            ConnectivityPathKind::InternetDirect => 2,
            ConnectivityPathKind::Relay => 3,
        },
    })
}

fn optional_suffix(input: &[u8]) -> Result<Option<DnsDomainSuffix>, NetworkAdapterError> {
    if input.is_empty() {
        return Ok(None);
    }
    DnsDomainSuffix::new(utf8(input)?)
        .map(Some)
        .map_err(|_| NetworkAdapterError::Dns)
}

fn dns_valid(
    enabled: bool,
    device_naming: bool,
    device_domain: &[u8],
    resolver_address: &[u8],
    resolver_port: i32,
    split_domain: &[u8],
) -> bool {
    let result = (|| -> Result<PrivateDnsConfig, NetworkAdapterError> {
        let mode = if enabled {
            PrivateDnsMode::Enabled
        } else {
            PrivateDnsMode::Disabled
        };
        let device_domain = optional_suffix(device_domain)?;
        let split_domains = optional_suffix(split_domain)?.into_iter().collect();
        let resolvers = if resolver_address.is_empty() {
            if resolver_port != 0 {
                return Err(NetworkAdapterError::Dns);
            }
            Vec::new()
        } else {
            let address = utf8(resolver_address)?
                .parse::<IpAddr>()
                .map_err(|_| NetworkAdapterError::Dns)?;
            let endpoint = ResolverEndpoint::new(
                address,
                port(resolver_port).map_err(|_| NetworkAdapterError::Dns)?,
            )
            .map_err(|_| NetworkAdapterError::Dns)?;
            vec![endpoint]
        };
        PrivateDnsConfig::new(mode, device_naming, device_domain, resolvers, split_domains)
            .map_err(|_| NetworkAdapterError::Dns)
    })();
    result.is_ok()
}

fn jni_output<'caller>(
    unowned_env: &mut EnvUnowned<'caller>,
    operation: impl FnOnce() -> Vec<u8>,
) -> JByteArray<'caller> {
    unowned_env
        .with_env(|env| env.byte_array_from_slice(&operation()))
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_forwardOpenPayload<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    id: jlong,
    family_code: jint,
    bind_port: jint,
    target_address: JByteArray<'caller>,
    target_port: jint,
) -> JByteArray<'caller> {
    unowned_env
        .with_env(|env| -> jni::errors::Result<_> {
            let target_address = env.convert_byte_array(&target_address)?;
            let payload =
                encode_forward_open(id, family_code, bind_port, &target_address, target_port)
                    .unwrap_or_default();
            env.byte_array_from_slice(&payload)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_forwardClosePayload<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    id: jlong,
) -> JByteArray<'caller> {
    jni_output(&mut env, || encode_forward_close(id).unwrap_or_default())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_isForwardingPayload<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    payload: JByteArray<'caller>,
) -> jboolean {
    unowned_env
        .with_env(|env| -> jni::errors::Result<_> {
            let payload = env.convert_byte_array(&payload)?;
            Ok(is_forward_payload(&payload))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_connectivitySelectedPath<
    'caller,
>(
    _env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    local: jint,
    internet: jint,
    relay: jint,
) -> jint {
    selected_path_code(local, internet, relay).unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_validatePrivateDnsConfig<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    enabled: jboolean,
    device_naming: jboolean,
    device_domain: JByteArray<'caller>,
    resolver_address: JByteArray<'caller>,
    resolver_port: jint,
    split_domain: JByteArray<'caller>,
) -> jboolean {
    unowned_env
        .with_env(|env| -> jni::errors::Result<_> {
            let device_domain = env.convert_byte_array(&device_domain)?;
            let resolver_address = env.convert_byte_array(&resolver_address)?;
            let split_domain = env.convert_byte_array(&split_domain)?;
            Ok(dns_valid(
                enabled,
                device_naming,
                &device_domain,
                &resolver_address,
                resolver_port,
                &split_domain,
            ))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarding_payloads_reuse_exact_phase143_bridge_operations() {
        let open =
            encode_forward_open(149, 0, 41_149, b"127.0.0.1", 22).expect("valid forward open");
        let expected = BridgeCommand::ForwardOpen {
            forward_id: PortForwardId::new(149).expect("id"),
            spec: TcpForwardSpec::new(
                LoopbackBind::new(LoopbackFamily::Ipv4, 41_149).expect("bind"),
                ForwardTarget::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 22).expect("target"),
            ),
        };
        assert_eq!(BridgeCommand::decode(&open).expect("decode"), expected);
        assert!(is_forward_payload(&open));

        let ipv6 = encode_forward_open(150, 1, 41_150, b"::1", 443).expect("valid ipv6 forward");
        assert!(matches!(
            BridgeCommand::decode(&ipv6).expect("decode ipv6"),
            BridgeCommand::ForwardOpen { .. }
        ));

        let close = encode_forward_close(149).expect("close");
        assert_eq!(
            BridgeCommand::decode(&close).expect("decode close"),
            BridgeCommand::ForwardClose(PortForwardId::new(149).expect("id"))
        );
    }

    #[test]
    fn forwarding_inputs_fail_closed_through_existing_authorities() {
        assert!(encode_forward_open(0, 0, 41_149, b"127.0.0.1", 22).is_err());
        assert!(encode_forward_open(-1, 0, 41_149, b"127.0.0.1", 22).is_err());
        assert!(encode_forward_open(149, 9, 41_149, b"127.0.0.1", 22).is_err());
        assert!(encode_forward_open(149, 0, 0, b"127.0.0.1", 22).is_err());
        assert!(encode_forward_open(149, 0, 65_536, b"127.0.0.1", 22).is_err());
        assert!(encode_forward_open(149, 0, 41_149, b"127.0.0.1", 0).is_err());
        assert!(encode_forward_open(149, 0, 41_149, b"example.com", 22).is_err());
        assert!(encode_forward_open(149, 0, 41_149, b"0.0.0.0", 22).is_err());
        assert!(encode_forward_open(149, 0, 41_149, b"224.0.0.1", 22).is_err());
        assert!(encode_forward_open(149, 0, 41_149, b"255.255.255.255", 22).is_err());
    }

    #[test]
    fn connectivity_selection_reuses_existing_deterministic_authority() {
        assert_eq!(selected_path_code(0, 0, 0).expect("offline"), 0);
        assert_eq!(selected_path_code(1, 1, 1).expect("local"), 1);
        assert_eq!(selected_path_code(2, 1, 1).expect("internet"), 2);
        assert_eq!(selected_path_code(2, 2, 1).expect("relay"), 3);
        assert!(selected_path_code(9, 1, 1).is_err());
    }

    #[test]
    fn private_dns_validation_is_typed_optional_and_non_mutating() {
        assert!(dns_valid(false, false, b"", b"", 0, b""));
        assert!(dns_valid(
            true,
            true,
            b"prw.internal",
            b"127.0.0.1",
            53,
            b"dev.internal",
        ));
        assert!(!dns_valid(true, true, b"", b"127.0.0.1", 53, b""));
        assert!(!dns_valid(false, false, b"PRW.internal", b"", 0, b""));
        assert!(!dns_valid(false, false, b"", b"resolver.local", 53, b""));
        assert!(!dns_valid(false, false, b"", b"", 0, b"dev.internal"));

        let before = selected_path_code(2, 1, 1).expect("before DNS");
        assert!(dns_valid(true, false, b"", b"127.0.0.1", 53, b""));
        let after = selected_path_code(2, 1, 1).expect("after DNS");
        assert_eq!(before, after);
    }
}
