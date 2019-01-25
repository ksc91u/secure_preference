package org.ksc91u.securepreference

import android.annotation.SuppressLint
import android.content.Context
import android.content.DialogInterface
import android.content.SharedPreferences
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.github.pwittchen.rxbiometric.library.RxBiometricBuilder
import com.github.pwittchen.rxbiometric.library.validation.RxPreconditions
import io.reactivex.Single
import io.reactivex.android.schedulers.AndroidSchedulers
import io.reactivex.disposables.CompositeDisposable
import java.math.BigInteger
import java.security.*
import java.util.*
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import javax.security.auth.x500.X500Principal

class SecurePreference(
    private val nameSpace: String,
    private val activity: FragmentActivity,
    private val symmetricEncryption: String = "AES",
    val symmetricPadding: String = "NoPadding",
    val symmetricBlockMode: String = "GCM"
) {

    private lateinit var preference: SharedPreferences

    private val disposable: CompositeDisposable = CompositeDisposable()
    private var secretKey: SecretKey? = null
    private var rsaPrivate: PrivateKey? = null
    private var rsaPublic: PublicKey? = null
    private val secureRandom = SecureRandom()
    private val cipherMode: String by lazy { "$symmetricEncryption/$symmetricBlockMode/$symmetricPadding" }
    private val ivRequired: Int by lazy {
        if (symmetricBlockMode == "ECB") {
            0
        } else if (symmetricEncryption == "BLOWFISH") {
            8
        } else {
            16
        }
    }

    private val propertyBlockMode by lazy {
        when (symmetricBlockMode) {
            KeyProperties.BLOCK_MODE_ECB -> KeyProperties.BLOCK_MODE_ECB
            KeyProperties.BLOCK_MODE_CBC -> KeyProperties.BLOCK_MODE_CBC
            KeyProperties.BLOCK_MODE_CTR -> KeyProperties.BLOCK_MODE_CTR
            else -> KeyProperties.BLOCK_MODE_GCM
        }
    }

    private val propertyPadding by lazy {
        when (symmetricPadding) {
            KeyProperties.ENCRYPTION_PADDING_NONE -> KeyProperties.ENCRYPTION_PADDING_NONE
            KeyProperties.ENCRYPTION_PADDING_PKCS7 -> KeyProperties.ENCRYPTION_PADDING_PKCS7
            KeyProperties.ENCRYPTION_PADDING_RSA_OAEP -> KeyProperties.ENCRYPTION_PADDING_RSA_OAEP
            else -> KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
        }
    }

    private var symmetricSalt32Bytes = ByteArray(32)

    companion object {
        const val KEY_ALGORITHM_RSA = "RSA"

        const val AES_CBC_PKCS5 = "AES/CBC/PKCS5Padding"
        const val AES_GCM_NONE = "AES/GCM/NoPadding"
        const val AES_CTR_PKCS5 = "AES/CTR/PKCS5Padding"
        const val RSA_ECB_PKCS1 = "RSA/ECB/PKCS1Padding"
        const val BLOWFISH_CTR_PKCS5 = "BLOWFISH/CTR/PKCS5Padding"
        const val AES = "AES"
    }


    init {
        if (nameSpace.isEmpty()) {
            throw IllegalArgumentException("Need to specify a nameSpace")
        }

        preference = activity.getSharedPreferences("secure_$nameSpace", Context.MODE_PRIVATE)

        initRsaKey()
        initSymmetricSalt()
    }

    protected fun finalize() {
        disposable.dispose()
    }

    private fun initSymmetricSalt() {
        var byte16_0 = ByteArray(16)
        var byte16_1 = ByteArray(16)
        val keyName = "$nameSpace$symmetricEncryption"
        val rsaDecCipherDecrypt = Cipher.getInstance(RSA_ECB_PKCS1).apply {
            init(Cipher.DECRYPT_MODE, rsaPrivate)
        }

        if (preference.contains("0_$keyName") && preference.contains("1_$keyName")) {
            val salt0 = preference.getString("0_$keyName", "")
            val salt1 = preference.getString("1_$keyName", "")

            symmetricSalt32Bytes = rsaDecCipherDecrypt.doFinal(Base64.decode(salt0, Base64.NO_PADDING))
                .plus(rsaDecCipherDecrypt.doFinal(Base64.decode(salt1, Base64.NO_PADDING)))
            return
        }
        preference.edit().remove("0_$keyName").remove("1_$keyName").apply()

        secureRandom.nextBytes(byte16_0)
        secureRandom.nextBytes(byte16_1)

        var rsaEncCipher = Cipher.getInstance(RSA_ECB_PKCS1).apply {
            init(Cipher.ENCRYPT_MODE, rsaPublic)
        }

        val aes0 = Base64.encodeToString(rsaEncCipher.doFinal(byte16_0), Base64.NO_PADDING)
        val aes1 = Base64.encodeToString(rsaEncCipher.doFinal(byte16_1), Base64.NO_PADDING)
        preference.edit().putString("0_$keyName", aes0).putString("1_$keyName", aes1).apply()

        symmetricSalt32Bytes = byte16_0.plus(byte16_1)

    }

    @SuppressLint("WrongConstant")
    private fun initRsaKey() {
        val rsaKeyName = "RSA_$nameSpace"
        val androidKeyStore = KeyStore.getInstance("AndroidKeyStore")
        androidKeyStore.load(null)
        if (androidKeyStore.containsAlias(rsaKeyName)) {
            rsaPrivate = (androidKeyStore.getKey(rsaKeyName, null) as PrivateKey)
            if (rsaPrivate == null) {
                throw IllegalStateException("Failed to retrive RSA key RSA_$nameSpace from AndroidKeyStore, this should not happen.")
            }
            val cert = androidKeyStore.getCertificate(rsaKeyName)
            rsaPublic = cert.publicKey
            return
        }

        val kpg = KeyPairGenerator.getInstance(KEY_ALGORITHM_RSA, "AndroidKeyStore")
        val keySpecBuilder = KeyPairGeneratorSpec.Builder(activity)
            .setAlias(rsaKeyName)
            .setKeySize(3072)
            .setSubject(X500Principal("CN=$nameSpace"))
            .setSerialNumber(BigInteger.ONE)
            .setStartDate(Date(1970, 1, 1, 1, 1, 1))
            .setEndDate(Date(2100, 1, 1, 1, 1, 1))
        if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            keySpecBuilder.setKeyType(KeyProperties.KEY_ALGORITHM_RSA)
        } else {
            keySpecBuilder.setKeyType(KEY_ALGORITHM_RSA)
        }
        kpg.initialize(keySpecBuilder.build())
        val pair = kpg.genKeyPair()
        rsaPrivate = pair.private
        rsaPublic = pair.public
    }

    private fun digestPassCode(passcode: String): ByteArray {
        val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        val spec = PBEKeySpec(passcode.toCharArray(), symmetricSalt32Bytes, 4000, 256)
        val secret = secretKeyFactory.generateSecret(spec)
        return secret.encoded
    }

    fun encryptWithPasscode(passcode: String, clearTextBytes: ByteArray): ByteArray {
        var iv = ByteArray(ivRequired)
        secureRandom.nextBytes(iv)

        val skeySpec = SecretKeySpec(digestPassCode(passcode), symmetricEncryption)
        val cipher = Cipher.getInstance(cipherMode)
        if (ivRequired == 0) {
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec)
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, IvParameterSpec(iv))
        }

        return iv + cipher.doFinal(clearTextBytes)
    }

    @Throws(BadPaddingException::class)
    fun decryptWithPasscode(passcode: String, encTextBytes: ByteArray): ByteArray {
        val pair: Pair<ByteArray, ByteArray> = if (ivRequired == 0) {
            Pair(ByteArray(0), encTextBytes)
        } else {
            Pair(
                encTextBytes.sliceArray(IntRange(0, ivRequired - 1)),
                encTextBytes.sliceArray(IntRange(16, encTextBytes.size - 1))
            )
        }

        val skeySpec = SecretKeySpec(digestPassCode(passcode), symmetricEncryption)
        val cipher = Cipher.getInstance(cipherMode)
        if (ivRequired == 0) {
            cipher.init(Cipher.DECRYPT_MODE, skeySpec)
        } else {
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, IvParameterSpec(pair.first))
        }

        return cipher.doFinal(pair.second)
    }


    @RequiresApi(Build.VERSION_CODES.M)
    fun encryptWithBiometrics(
        clearTextBytes: ByteArray
    ): Single<Pair<ByteArray, ByteArray>> {
        if (secretKey == null) {
            Toast.makeText(activity, "Run initBiometrics first", Toast.LENGTH_LONG).show()
            return Single.error(IllegalStateException("Run initBiometrics first"))
        }
        val cipher = Cipher.getInstance(
            symmetricEncryption + "/"
                    + symmetricBlockMode + "/"
                    + symmetricPadding
        )
            .apply {
                init(Cipher.ENCRYPT_MODE, secretKey)
            }
        var cryptoObject = BiometricPrompt.CryptoObject(cipher)
        return RxBiometricBuilder()
            .title("Encrypt")
            .description("Encrypt")
            .negativeButtonText("cancel")
            .negativeButtonListener(DialogInterface.OnClickListener { p0, p1 ->
            })
            .build()
            .authenticate(activity, cryptoObject)
            .observeOn(AndroidSchedulers.mainThread())
            .map { authResult ->
                if (authResult.cryptoObject == null) {
                    throw java.lang.IllegalStateException("CryptoObject should not be null")
                } else {
                    val cipher = authResult.cryptoObject!!.cipher!!
                    val result = cipher.doFinal(clearTextBytes)
                    val iv = cipher.iv
                    return@map Pair(result, iv)
                }
            }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun decryptWithBiometrics(
        encryptTextAndIv: Pair<ByteArray, ByteArray>
    ): Single<ByteArray> {
        if (secretKey == null) {
            Toast.makeText(activity, "Run initBiometrics first", Toast.LENGTH_LONG).show()
            return Single.error(IllegalStateException("Run initBiometrics first"))
        }
        val cipher = Cipher.getInstance(
            symmetricEncryption + "/"
                    + symmetricBlockMode + "/"
                    + symmetricPadding
        )
            .apply {
                //https://stackoverflow.com/questions/33995233/android-aes-encryption-decryption-using-gcm-mode-in-android
                if (symmetricBlockMode == "GCM") {
                    init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, encryptTextAndIv.second))
                } else if (symmetricBlockMode == "ECB") {
                    init(Cipher.DECRYPT_MODE, secretKey)
                } else {
                    init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(encryptTextAndIv.second))
                }
            }
        var cryptoObject = BiometricPrompt.CryptoObject(cipher)
        return RxBiometricBuilder()
            .title("Decrypt")
            .description("Decrypt")
            .negativeButtonText("cancel")
            .negativeButtonListener(DialogInterface.OnClickListener { p0, p1 ->
            })
            .build()
            .authenticate(activity, cryptoObject)
            .observeOn(AndroidSchedulers.mainThread())
            .map { authResult ->
                if (authResult.cryptoObject == null) {
                    throw java.lang.IllegalStateException("CryptoObject should not be null")
                } else {
                    val cipherFromResult = authResult.cryptoObject!!.cipher!!
                    val result = cipherFromResult.doFinal(encryptTextAndIv.first)
                    return@map result
                }
            }
    }


    fun initBiometrics(): Single<Boolean> {
        if(Build.VERSION.SDK_INT < Build.VERSION_CODES.M){
            return Single.just(false)
        }
        return RxPreconditions.canHandleBiometric(activity)
            .observeOn(AndroidSchedulers.mainThread())
            .map {
                if (!it) {
                    throw java.lang.IllegalStateException("No biometric support")
                } else {
                    secretKey = getSymmetricKey(nameSpace)
                }
                return@map it
            }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun getSymmetricKey(keyAlias: String): SecretKey {
        val androidKeyStore = KeyStore.getInstance("AndroidKeyStore")
        androidKeyStore.load(null)
        if (androidKeyStore.containsAlias(keyAlias)) {
            return androidKeyStore.getKey(keyAlias, null) as SecretKey
        }


        var keyGenerator = KeyGenerator.getInstance(symmetricEncryption, "AndroidKeyStore")
            .apply {

                val builder = KeyGenParameterSpec.Builder(
                    keyAlias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                val keySpec = builder.setKeySize(256)
                    .setBlockModes(propertyBlockMode)
                    .setEncryptionPaddings(propertyPadding)
                    .setRandomizedEncryptionRequired(true)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationValidityDurationSeconds(5 * 60)
                    .build()
                init(keySpec)
            }
        return keyGenerator.generateKey()
    }

    fun putString(key: String, value: String): Single<Boolean> {
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return encryptWithBiometrics(value.toByteArray())
                .doOnSuccess {
                    preference.edit().putString(key, Base64.encodeToString(it.first, Base64.URL_SAFE))
                        .putString(key + "_iv", Base64.encodeToString(it.second, Base64.URL_SAFE)).apply()
                }.map {
                    return@map true
                }
        }else{
            return Single.just(false)
        }
    }

    fun getString(key: String): Single<String> {
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val value = Base64.decode(preference.getString(key, ""), Base64.URL_SAFE)
            val iv = Base64.decode(preference.getString(key + "_iv", ""), Base64.URL_SAFE)
            return decryptWithBiometrics(Pair(value, iv)).map {
                return@map String(it)
            }
        }else{
            return Single.just("")
        }
    }

}