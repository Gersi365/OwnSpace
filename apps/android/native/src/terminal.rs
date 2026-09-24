use jni::{
    EnvUnowned,
    errors::ThrowRuntimeExAndDefault,
    objects::{JByteArray, JClass},
    sys::{jboolean, jint, jlong},
};
use prw_remote_bridge::{BridgeCommand, MAX_BRIDGE_INLINE_BYTES};
use prw_terminal::{TerminalGeometry, TerminalProfile, TerminalSessionId};

const MAX_ANDROID_TERMINAL_IO_BYTES: usize = MAX_BRIDGE_INLINE_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalAdapterError {
    SessionId,
    Profile,
    Geometry,
    Input,
    Read,
    Bridge,
}

fn session_id(value: i64) -> Result<TerminalSessionId, TerminalAdapterError> {
    let value = u64::try_from(value).map_err(|_| TerminalAdapterError::SessionId)?;
    TerminalSessionId::new(value).map_err(|_| TerminalAdapterError::SessionId)
}

const fn profile(value: i32) -> Result<TerminalProfile, TerminalAdapterError> {
    match value {
        0 => Ok(TerminalProfile::PosixShell),
        1 => Ok(TerminalProfile::BashShell),
        _ => Err(TerminalAdapterError::Profile),
    }
}

fn geometry(columns: i32, rows: i32) -> Result<TerminalGeometry, TerminalAdapterError> {
    let columns = u16::try_from(columns).map_err(|_| TerminalAdapterError::Geometry)?;
    let rows = u16::try_from(rows).map_err(|_| TerminalAdapterError::Geometry)?;
    TerminalGeometry::new(columns, rows).map_err(|_| TerminalAdapterError::Geometry)
}

fn bridge_payload(command: &BridgeCommand) -> Result<Vec<u8>, TerminalAdapterError> {
    command.encode().map_err(|_| TerminalAdapterError::Bridge)
}

fn encode_terminal_open(
    session: i64,
    profile_code: i32,
    columns: i32,
    rows: i32,
) -> Result<Vec<u8>, TerminalAdapterError> {
    bridge_payload(&BridgeCommand::TerminalOpen {
        session_id: session_id(session)?,
        profile: profile(profile_code)?,
        geometry: geometry(columns, rows)?,
    })
}

fn encode_terminal_input(session: i64, input: &[u8]) -> Result<Vec<u8>, TerminalAdapterError> {
    if input.is_empty() || input.len() > MAX_ANDROID_TERMINAL_IO_BYTES {
        return Err(TerminalAdapterError::Input);
    }
    bridge_payload(&BridgeCommand::TerminalInput {
        session_id: session_id(session)?,
        bytes: input.to_vec(),
    })
}

fn encode_terminal_resize(
    session: i64,
    columns: i32,
    rows: i32,
) -> Result<Vec<u8>, TerminalAdapterError> {
    bridge_payload(&BridgeCommand::TerminalResize {
        session_id: session_id(session)?,
        geometry: geometry(columns, rows)?,
    })
}

fn encode_terminal_read(session: i64, maximum_bytes: i32) -> Result<Vec<u8>, TerminalAdapterError> {
    let maximum_bytes = usize::try_from(maximum_bytes).map_err(|_| TerminalAdapterError::Read)?;
    if maximum_bytes == 0 || maximum_bytes > MAX_ANDROID_TERMINAL_IO_BYTES {
        return Err(TerminalAdapterError::Read);
    }
    bridge_payload(&BridgeCommand::TerminalRead {
        session_id: session_id(session)?,
        maximum_bytes,
    })
}

fn encode_terminal_close(session: i64) -> Result<Vec<u8>, TerminalAdapterError> {
    bridge_payload(&BridgeCommand::TerminalClose(session_id(session)?))
}

fn is_terminal_payload(payload: &[u8]) -> bool {
    matches!(
        BridgeCommand::decode(payload),
        Ok(BridgeCommand::TerminalOpen { .. }
            | BridgeCommand::TerminalInput { .. }
            | BridgeCommand::TerminalResize { .. }
            | BridgeCommand::TerminalRead { .. }
            | BridgeCommand::TerminalClose(_))
    )
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
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_terminalOpenPayload<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    session: jlong,
    profile_code: jint,
    columns: jint,
    rows: jint,
) -> JByteArray<'caller> {
    jni_output(&mut env, || {
        encode_terminal_open(session, profile_code, columns, rows).unwrap_or_default()
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_terminalInputPayload<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    session: jlong,
    input: JByteArray<'caller>,
) -> JByteArray<'caller> {
    unowned_env
        .with_env(|env| -> jni::errors::Result<_> {
            let input = env.convert_byte_array(&input)?;
            let payload = encode_terminal_input(session, &input).unwrap_or_default();
            env.byte_array_from_slice(&payload)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_terminalResizePayload<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    session: jlong,
    columns: jint,
    rows: jint,
) -> JByteArray<'caller> {
    jni_output(&mut env, || {
        encode_terminal_resize(session, columns, rows).unwrap_or_default()
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_terminalReadPayload<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    session: jlong,
    maximum_bytes: jint,
) -> JByteArray<'caller> {
    jni_output(&mut env, || {
        encode_terminal_read(session, maximum_bytes).unwrap_or_default()
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_terminalClosePayload<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    session: jlong,
) -> JByteArray<'caller> {
    jni_output(&mut env, || {
        encode_terminal_close(session).unwrap_or_default()
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privateworkspace_prw_NativeBridge_isTerminalPayload<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    payload: JByteArray<'caller>,
) -> jboolean {
    unowned_env
        .with_env(|env| -> jni::errors::Result<_> {
            let payload = env.convert_byte_array(&payload)?;
            Ok(is_terminal_payload(&payload))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[cfg(test)]
mod tests {
    use prw_remote_bridge::BridgeCommand;
    use prw_terminal::{TerminalGeometry, TerminalProfile, TerminalSessionId};

    use super::*;

    #[test]
    fn all_terminal_payloads_round_trip_through_existing_bridge_codec() {
        let id = TerminalSessionId::new(147).expect("terminal id");
        let geometry = TerminalGeometry::new(80, 24).expect("geometry");

        let open = encode_terminal_open(147, 0, 80, 24).expect("open payload");
        assert_eq!(
            BridgeCommand::decode(&open).expect("decode open"),
            BridgeCommand::TerminalOpen {
                session_id: id,
                profile: TerminalProfile::PosixShell,
                geometry,
            }
        );

        let input = encode_terminal_input(147, b"printf phase147\\n").expect("input payload");
        assert_eq!(
            BridgeCommand::decode(&input).expect("decode input"),
            BridgeCommand::TerminalInput {
                session_id: id,
                bytes: b"printf phase147\\n".to_vec(),
            }
        );

        let resize = encode_terminal_resize(147, 120, 40).expect("resize payload");
        assert_eq!(
            BridgeCommand::decode(&resize).expect("decode resize"),
            BridgeCommand::TerminalResize {
                session_id: id,
                geometry: TerminalGeometry::new(120, 40).expect("resize geometry"),
            }
        );

        let read = encode_terminal_read(147, 4096).expect("read payload");
        assert_eq!(
            BridgeCommand::decode(&read).expect("decode read"),
            BridgeCommand::TerminalRead {
                session_id: id,
                maximum_bytes: 4096,
            }
        );

        let close = encode_terminal_close(147).expect("close payload");
        assert_eq!(
            BridgeCommand::decode(&close).expect("decode close"),
            BridgeCommand::TerminalClose(id)
        );

        for payload in [&open, &input, &resize, &read, &close] {
            assert!(is_terminal_payload(payload));
        }
    }

    #[test]
    fn invalid_terminal_values_fail_closed() {
        assert_eq!(
            encode_terminal_open(0, 0, 80, 24),
            Err(TerminalAdapterError::SessionId)
        );
        assert_eq!(
            encode_terminal_open(-1, 0, 80, 24),
            Err(TerminalAdapterError::SessionId)
        );
        assert_eq!(
            encode_terminal_open(1, 2, 80, 24),
            Err(TerminalAdapterError::Profile)
        );
        assert_eq!(
            encode_terminal_open(1, 0, 0, 24),
            Err(TerminalAdapterError::Geometry)
        );
        assert_eq!(
            encode_terminal_resize(1, 1001, 24),
            Err(TerminalAdapterError::Geometry)
        );
        assert_eq!(
            encode_terminal_input(1, b""),
            Err(TerminalAdapterError::Input)
        );
        assert_eq!(
            encode_terminal_input(1, &vec![0; MAX_ANDROID_TERMINAL_IO_BYTES + 1]),
            Err(TerminalAdapterError::Input)
        );
        assert_eq!(encode_terminal_read(1, 0), Err(TerminalAdapterError::Read));
        assert_eq!(
            encode_terminal_read(
                1,
                i32::try_from(MAX_ANDROID_TERMINAL_IO_BYTES + 1).expect("bound")
            ),
            Err(TerminalAdapterError::Read)
        );
    }

    #[test]
    fn terminal_recognizer_rejects_non_terminal_bridge_payload() {
        let agent_status = BridgeCommand::AgentStatus.encode().expect("agent status");
        assert!(!is_terminal_payload(&agent_status));
        assert!(!is_terminal_payload(b"not-prwc"));
    }
}
