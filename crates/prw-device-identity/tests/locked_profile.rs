use aws_lc_rs::{
    encoding::AsDer,
    rand::SystemRandom,
    signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING,
        ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, KeyPair,
    },
};
use prw_control_plane::{
    DeviceIdentityAlgorithm, DeviceIdentityPublicKeyEncoding, DeviceIdentitySignature,
    DeviceIdentitySignatureEncoding, PublicIdentityMaterial,
};
use prw_device_identity::{DeviceIdentityVerificationError, verify_device_identity_signature};

const MESSAGE: &[u8] = b"private-remote-workspace production device identity verification";
const EC_PUBLIC_KEY_OID_DER: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const P256_CURVE_OID_DER: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const UNCOMPRESSED_POINT_PREFIX: &[u8] = &[0x03, 0x42, 0x00, 0x04];

fn identity_from_der(der: Vec<u8>) -> PublicIdentityMaterial {
    PublicIdentityMaterial::new(
        DeviceIdentityAlgorithm::EcdsaP256Sha256,
        DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
        der,
    )
    .expect("test public identity is non-empty")
}

fn signature_from_bytes(bytes: Vec<u8>) -> DeviceIdentitySignature {
    DeviceIdentitySignature::new(
        DeviceIdentityAlgorithm::EcdsaP256Sha256,
        DeviceIdentitySignatureEncoding::EcdsaSigValueDer,
        bytes,
    )
    .expect("test signature is non-empty")
}

fn p256_fixture() -> (EcdsaKeyPair, PublicIdentityMaterial) {
    let key_pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)
        .expect("generate disposable P-256 test key");
    let public_der = key_pair
        .public_key()
        .as_der()
        .expect("serialize disposable public key as SPKI DER");
    let identity = identity_from_der(public_der.as_ref().to_vec());
    (key_pair, identity)
}

fn replace_once(bytes: &mut [u8], needle: &[u8], replacement_last: u8) {
    let index = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("expected DER marker exists");
    bytes[index + needle.len() - 1] = replacement_last;
}

fn signature_for(key_pair: &EcdsaKeyPair, message: &[u8]) -> DeviceIdentitySignature {
    let rng = SystemRandom::new();
    let signature = key_pair
        .sign(&rng, message)
        .expect("sign with disposable test key");
    signature_from_bytes(signature.as_ref().to_vec())
}

#[test]
fn verifies_valid_p256_spki_and_der_signature() {
    let (key_pair, identity) = p256_fixture();
    let signature = signature_for(&key_pair, MESSAGE);

    assert_eq!(
        verify_device_identity_signature(&identity, MESSAGE, &signature),
        Ok(())
    );
}

#[test]
fn rejects_raw_sec1_point_even_if_provider_can_parse_it() {
    let (key_pair, _) = p256_fixture();
    let identity = identity_from_der(key_pair.public_key().as_ref().to_vec());
    let signature = signature_for(&key_pair, MESSAGE);

    assert_eq!(
        verify_device_identity_signature(&identity, MESSAGE, &signature),
        Err(DeviceIdentityVerificationError::NonCanonicalPublicKeyEncoding)
    );
}

#[test]
fn rejects_malformed_spki_der() {
    let (key_pair, identity) = p256_fixture();
    let mut bytes = identity.as_bytes().to_vec();
    bytes[0] = 0x31;
    let malformed = identity_from_der(bytes);
    let signature = signature_for(&key_pair, MESSAGE);

    assert_eq!(
        verify_device_identity_signature(&malformed, MESSAGE, &signature),
        Err(DeviceIdentityVerificationError::InvalidPublicKey)
    );
}

#[test]
fn rejects_spki_with_trailing_bytes() {
    let (key_pair, identity) = p256_fixture();
    let mut bytes = identity.as_bytes().to_vec();
    bytes.push(0x00);
    let trailing = identity_from_der(bytes);
    let signature = signature_for(&key_pair, MESSAGE);

    assert!(matches!(
        verify_device_identity_signature(&trailing, MESSAGE, &signature),
        Err(DeviceIdentityVerificationError::InvalidPublicKey
            | DeviceIdentityVerificationError::NonCanonicalPublicKeyEncoding)
    ));
}

#[test]
fn rejects_wrong_public_key_algorithm_oid() {
    let (key_pair, identity) = p256_fixture();
    let mut bytes = identity.as_bytes().to_vec();
    replace_once(&mut bytes, EC_PUBLIC_KEY_OID_DER, 0x02);
    let wrong_oid = identity_from_der(bytes);
    let signature = signature_for(&key_pair, MESSAGE);

    assert_eq!(
        verify_device_identity_signature(&wrong_oid, MESSAGE, &signature),
        Err(DeviceIdentityVerificationError::InvalidPublicKey)
    );
}

#[test]
fn rejects_wrong_named_curve_oid() {
    let (key_pair, identity) = p256_fixture();
    let mut bytes = identity.as_bytes().to_vec();
    replace_once(&mut bytes, P256_CURVE_OID_DER, 0x08);
    let wrong_curve = identity_from_der(bytes);
    let signature = signature_for(&key_pair, MESSAGE);

    assert_eq!(
        verify_device_identity_signature(&wrong_curve, MESSAGE, &signature),
        Err(DeviceIdentityVerificationError::InvalidPublicKey)
    );
}

#[test]
fn rejects_off_curve_public_point() {
    let (key_pair, identity) = p256_fixture();
    let mut bytes = identity.as_bytes().to_vec();
    let marker = bytes
        .windows(UNCOMPRESSED_POINT_PREFIX.len())
        .position(|window| window == UNCOMPRESSED_POINT_PREFIX)
        .expect("SPKI contains uncompressed P-256 point");
    let coordinates_start = marker + UNCOMPRESSED_POINT_PREFIX.len();
    bytes[coordinates_start..coordinates_start + 64].fill(0);
    let invalid_point = identity_from_der(bytes);
    let signature = signature_for(&key_pair, MESSAGE);

    assert_eq!(
        verify_device_identity_signature(&invalid_point, MESSAGE, &signature),
        Err(DeviceIdentityVerificationError::InvalidPublicKey)
    );
}

#[test]
fn rejects_p384_key_under_p256_profile() {
    let key_pair = EcdsaKeyPair::generate(&ECDSA_P384_SHA384_ASN1_SIGNING)
        .expect("generate disposable P-384 test key");
    let public_der = key_pair
        .public_key()
        .as_der()
        .expect("serialize P-384 test key as SPKI DER");
    let identity = identity_from_der(public_der.as_ref().to_vec());
    let signature = signature_for(&key_pair, MESSAGE);

    assert_eq!(
        verify_device_identity_signature(&identity, MESSAGE, &signature),
        Err(DeviceIdentityVerificationError::InvalidPublicKey)
    );
}

#[test]
fn rejects_modified_message() {
    let (key_pair, identity) = p256_fixture();
    let signature = signature_for(&key_pair, MESSAGE);

    assert_eq!(
        verify_device_identity_signature(&identity, b"modified message", &signature),
        Err(DeviceIdentityVerificationError::InvalidSignature)
    );
}

#[test]
fn rejects_modified_signature() {
    let (key_pair, identity) = p256_fixture();
    let rng = SystemRandom::new();
    let signature = key_pair.sign(&rng, MESSAGE).expect("sign test message");
    let mut bytes = signature.as_ref().to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let signature = signature_from_bytes(bytes);

    assert_eq!(
        verify_device_identity_signature(&identity, MESSAGE, &signature),
        Err(DeviceIdentityVerificationError::InvalidSignature)
    );
}

#[test]
fn rejects_malformed_signature_der() {
    let (key_pair, identity) = p256_fixture();
    let rng = SystemRandom::new();
    let signature = key_pair.sign(&rng, MESSAGE).expect("sign test message");
    let mut bytes = signature.as_ref().to_vec();
    bytes.truncate(bytes.len() - 1);
    let signature = signature_from_bytes(bytes);

    assert_eq!(
        verify_device_identity_signature(&identity, MESSAGE, &signature),
        Err(DeviceIdentityVerificationError::InvalidSignature)
    );
}

#[test]
fn rejects_fixed_width_signature_claimed_as_der() {
    let key_pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING)
        .expect("generate disposable fixed-format P-256 test key");
    let public_der = key_pair
        .public_key()
        .as_der()
        .expect("serialize disposable public key as SPKI DER");
    let identity = identity_from_der(public_der.as_ref().to_vec());
    let signature = signature_for(&key_pair, MESSAGE);

    assert_eq!(
        verify_device_identity_signature(&identity, MESSAGE, &signature),
        Err(DeviceIdentityVerificationError::InvalidSignature)
    );
}
