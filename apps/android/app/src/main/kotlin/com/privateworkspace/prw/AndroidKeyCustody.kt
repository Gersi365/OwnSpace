[Reading 286 lines from start (total: 286 lines, 0 remaining)]

package com.privateworkspace.prw

import android.annotation.SuppressLint
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

internal enum class AndroidIdentityState {
    FirstRun,
    Established,
    ReenrollmentRequired,
}

internal fun classifyAndroidIdentityState(
    markerExists: Boolean,
    aliasExists: Boolean,
    expectedSpkiDigestExists: Boolean,
    spkiDigestMatches: Boolean,
): AndroidIdentityState = when {
    !markerExists && !aliasExists && !expectedSpkiDigestExists -> AndroidIdentityState.FirstRun
    markerExists && aliasExists && expectedSpkiDigestExists && spkiDigestMatches -> AndroidIdentityState.Established
    else -> AndroidIdentityState.ReenrollmentRequired
}

internal class AndroidReenrollmentRequiredException(
    message: String,
    cause: Throwable? = null,
) : IllegalStateException(message, cause)

// Direct Editor.commit() calls are intentional: identity-state persistence must
// expose commit failure so enrollment and re-enrollment can fail closed.
@SuppressLint("UseKtx")
internal class AndroidKeyCustody(
    context: Context,
    private val keyStore: KeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) },
) {
    private val identityState =
        context.getSharedPreferences(IDENTITY_STATE_PREFERENCES, Context.MODE_PRIVATE)

    fun loadEstablishedDeviceIdentitySpki(): ByteArray =
        loadEstablishedIdentitySpki(
            DEVICE_IDENTITY_ALIAS,
            DEVICE_IDENTITY_MARKER,
            DEVICE_IDENTITY_SPKI_DIGEST,
            "device",
        )

    fun loadEstablishedTransportIdentitySpki(): ByteArray =
        loadEstablishedIdentitySpki(
            TRANSPORT_IDENTITY_ALIAS,
            TRANSPORT_IDENTITY_MARKER,
            TRANSPORT_IDENTITY_SPKI_DIGEST,
            "transport",
        )

    /**
     * Explicit enrollment/re-enrollment boundary.
     *
     * This is the only device-identity path allowed to mint a new key. Resetting the
     * device identity also invalidates any previously established transport identity
     * so transport continuity is never inferred across a fresh device enrollment.
     */
    fun beginFreshDeviceEnrollment(): ByteArray {
        resetIdentity(
            TRANSPORT_IDENTITY_ALIAS,
            TRANSPORT_IDENTITY_MARKER,
            TRANSPORT_IDENTITY_SPKI_DIGEST,
            "transport",
        )
        return replaceIdentityForExplicitEnrollment(
            DEVICE_IDENTITY_ALIAS,
            DEVICE_IDENTITY_MARKER,
            DEVICE_IDENTITY_SPKI_DIGEST,
            "device",
        )
    }

    fun beginFreshTransportEnrollment(): ByteArray =
        replaceIdentityForExplicitEnrollment(
            TRANSPORT_IDENTITY_ALIAS,
            TRANSPORT_IDENTITY_MARKER,
            TRANSPORT_IDENTITY_SPKI_DIGEST,
            "transport",
        )

    fun deviceIdentityIsNonExportable(): Boolean = runCatching {
        loadEstablishedDeviceIdentitySpki()
        val privateKey = keyStore.getKey(DEVICE_IDENTITY_ALIAS, null) as? PrivateKey
            ?: return false
        privateKey.encoded == null
    }.getOrDefault(false)

    internal fun signCanonicalSessionProof(message: ByteArray): ByteArray =
        signTypedDeviceProof(message)

    internal fun signCanonicalEnrollmentProof(message: ByteArray): ByteArray =
        signTypedDeviceProof(message)

    private fun signTypedDeviceProof(message: ByteArray): ByteArray {
        require(message.isNotEmpty() && message.size <= MAX_TYPED_MESSAGE_BYTES)
        loadEstablishedDeviceIdentitySpki()
        return try {
            val privateKey = keyStore.getKey(DEVICE_IDENTITY_ALIAS, null) as? PrivateKey
                ?: throw AndroidReenrollmentRequiredException(
                    "Established Android device identity is unavailable; fresh re-enrollment is required",
                )
            check(privateKey.encoded == null) { "Android Keystore private key became exportable" }
            Signature.getInstance(SIGNATURE_ALGORITHM).run {
                initSign(privateKey)
                update(message)
                sign()
            }
        } catch (error: AndroidReenrollmentRequiredException) {
            throw error
        } catch (error: Throwable) {
            throw AndroidReenrollmentRequiredException(
                "Established Android device identity is unusable; fresh re-enrollment is required",
                error,
            )
        }
    }

    private fun inspectIdentityState(
        alias: String,
        marker: String,
        digestKey: String,
    ): AndroidIdentityState {
        val markerExists = identityState.getBoolean(marker, false)
        val expectedDigest = identityState.getString(digestKey, null)
        val aliasExists = runCatching { keyStore.containsAlias(alias) }.getOrDefault(false)
        val currentDigest = if (aliasExists && expectedDigest != null) {
            runCatching {
                keyStore.getCertificate(alias)?.publicKey?.encoded?.let(::spkiDigest)
            }.getOrNull()
        } else {
            null
        }
        return classifyAndroidIdentityState(
            markerExists = markerExists,
            aliasExists = aliasExists,
            expectedSpkiDigestExists = expectedDigest != null,
            spkiDigestMatches = expectedDigest != null && currentDigest == expectedDigest,
        )
    }

    private fun loadEstablishedIdentitySpki(
        alias: String,
        marker: String,
        digestKey: String,
        identityName: String,
    ): ByteArray {
        when (inspectIdentityState(alias, marker, digestKey)) {
            AndroidIdentityState.FirstRun -> throw AndroidReenrollmentRequiredException(
                "Android $identityName identity is not enrolled; explicit enrollment is required",
            )
            AndroidIdentityState.ReenrollmentRequired -> throw AndroidReenrollmentRequiredException(
                "Android $identityName identity state cannot be proven; fresh re-enrollment is required",
            )
            AndroidIdentityState.Established -> Unit
        }

        return try {
            val certificate = keyStore.getCertificate(alias)
                ?: throw AndroidReenrollmentRequiredException(
                    "Established Android $identityName public identity is unavailable; fresh re-enrollment is required",
                )
            val privateKey = keyStore.getKey(alias, null) as? PrivateKey
                ?: throw AndroidReenrollmentRequiredException(
                    "Established Android $identityName private identity is unavailable; fresh re-enrollment is required",
                )
            check(privateKey.encoded == null) { "Android Keystore private key became exportable" }
            certificate.publicKey.encoded
                ?: throw AndroidReenrollmentRequiredException(
                    "Established Android $identityName public identity is unreadable; fresh re-enrollment is required",
                )
        } catch (error: AndroidReenrollmentRequiredException) {
            throw error
        } catch (error: Throwable) {
            throw AndroidReenrollmentRequiredException(
                "Established Android $identityName identity is unusable; fresh re-enrollment is required",
                error,
            )
        }
    }

    private fun replaceIdentityForExplicitEnrollment(
        alias: String,
        marker: String,
        digestKey: String,
        identityName: String,
    ): ByteArray {
        resetIdentity(alias, marker, digestKey, identityName)
        check(inspectIdentityState(alias, marker, digestKey) == AndroidIdentityState.FirstRun) {
            "Android $identityName identity reset did not reach a clean first-run state"
        }
        return try {
            generate(alias, strongBox = true)
            val certificate = keyStore.getCertificate(alias)
                ?: error("Android Keystore public $identityName identity unavailable after creation")
            val privateKey = keyStore.getKey(alias, null) as? PrivateKey
                ?: error("Android Keystore private $identityName identity unavailable after creation")
            check(privateKey.encoded == null) { "Android Keystore private key became exportable" }
            val spki = certificate.publicKey.encoded
                ?: error("Android Keystore public $identityName identity SPKI unavailable")
            val digest = spkiDigest(spki)
            check(
                identityState.edit()
                    .putBoolean(marker, true)
                    .putString(digestKey, digest)
                    .commit(),
            ) {
                "Android $identityName established-state evidence could not be committed"
            }
            spki
        } catch (failure: Throwable) {
            runCatching { keyStore.deleteEntry(alias) }
            runCatching {
                identityState.edit().remove(marker).remove(digestKey).commit()
            }
            throw failure
        }
    }

    private fun resetIdentity(
        alias: String,
        marker: String,
        digestKey: String,
        identityName: String,
    ) {
        try {
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
        } catch (error: Throwable) {
            throw IllegalStateException("Android $identityName identity could not be reset safely", error)
        }
        check(identityState.edit().remove(marker).remove(digestKey).commit()) {
            "Android $identityName identity state could not be cleared safely"
        }
    }

    private fun spkiDigest(spki: ByteArray): String =
        Base64.getEncoder().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(spki),
        )

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

    companion object {
        internal const val DEVICE_IDENTITY_ALIAS = "prw.device-identity.v1"
        internal const val TRANSPORT_IDENTITY_ALIAS = "prw.transport-identity.v1"
        private const val IDENTITY_STATE_PREFERENCES = "prw.identity-state.v1"
        private const val DEVICE_IDENTITY_MARKER = "device-identity-established.v1"
        private const val DEVICE_IDENTITY_SPKI_DIGEST = "device-identity-spki-sha256.v1"
        private const val TRANSPORT_IDENTITY_MARKER = "transport-identity-established.v1"
        private const val TRANSPORT_IDENTITY_SPKI_DIGEST = "transport-identity-spki-sha256.v1"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        private const val MAX_TYPED_MESSAGE_BYTES = 4_442
    }
}

[executed on device: OWS (2e7ebe3b-518e-4a6a-b7f3-214616d73d77)]