package com.privateworkspace.prw

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

internal class AndroidKeyCustody(
    private val keyStore: KeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) },
) {
    fun ensureDeviceIdentitySpki(): ByteArray = ensurePublicSpki(DEVICE_IDENTITY_ALIAS)

    fun ensureTransportIdentitySpki(): ByteArray = ensurePublicSpki(TRANSPORT_IDENTITY_ALIAS)

    fun deviceIdentityIsNonExportable(): Boolean = isNonExportable(DEVICE_IDENTITY_ALIAS)

    internal fun signCanonicalSessionProof(message: ByteArray): ByteArray = signTypedDeviceProof(message)

    internal fun signCanonicalEnrollmentProof(message: ByteArray): ByteArray = signTypedDeviceProof(message)

    private fun signTypedDeviceProof(message: ByteArray): ByteArray {
        require(message.isNotEmpty() && message.size <= MAX_TYPED_MESSAGE_BYTES)
        ensurePublicSpki(DEVICE_IDENTITY_ALIAS)
        val privateKey = keyStore.getKey(DEVICE_IDENTITY_ALIAS, null) as? PrivateKey
            ?: error("device identity private key unavailable")
        check(privateKey.encoded == null) { "Android Keystore private key became exportable" }
        return Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(privateKey)
            update(message)
            sign()
        }
    }

    private fun ensurePublicSpki(alias: String): ByteArray {
        if (!keyStore.containsAlias(alias)) {
            generate(alias, strongBox = true)
        }
        val certificate = keyStore.getCertificate(alias)
            ?: error("Android Keystore public identity unavailable")
        return certificate.publicKey.encoded
            ?: error("Android Keystore public identity SPKI unavailable")
    }

    private fun generate(alias: String, strongBox: Boolean) {
        try {
            generator(alias, strongBox).generateKeyPair()
        } catch (error: StrongBoxUnavailableException) {
            if (!strongBox) throw error
            generator(alias, strongBox = false).generateKeyPair()
        }
    }

    private fun generator(alias: String, strongBox: Boolean): KeyPairGenerator =
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER).apply {
            val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
            if (strongBox) builder.setIsStrongBoxBacked(true)
            initialize(builder.build())
        }

    private fun isNonExportable(alias: String): Boolean {
        ensurePublicSpki(alias)
        val key = keyStore.getKey(alias, null) as? PrivateKey ?: return false
        return key.encoded == null
    }

    companion object {
        internal const val DEVICE_IDENTITY_ALIAS = "prw.device-identity.v1"
        internal const val TRANSPORT_IDENTITY_ALIAS = "prw.transport-identity.v1"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        private const val MAX_TYPED_MESSAGE_BYTES = 4_442
    }
}
