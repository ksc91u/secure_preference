package org.ksc91u.securepreference

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
import androidx.core.app.ActivityCompat
import androidx.fragment.app.FragmentActivity
import com.github.pwittchen.rxbiometric.library.RxBiometric
import com.github.pwittchen.rxbiometric.library.validation.RxPreconditions
import io.reactivex.Completable
import io.reactivex.Observable
import io.reactivex.Single
import io.reactivex.android.schedulers.AndroidSchedulers
import io.reactivex.disposables.CompositeDisposable
import io.reactivex.rxkotlin.addTo
import io.reactivex.rxkotlin.subscribeBy
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
    val nameSpace: String,
    val context: Context,
    val symmetricEncryption: String = "AES",
    val symmetricPadding: String = "NoPadding",
    val symmetricBlockMode: String = "GCM"
) {

    private lateinit var preference: SharedPreferences

    private val disposable: CompositeDisposable = CompositeDisposable()
    private var secretKey: SecretKey? = null
    private var rsaPrivate: PrivateKey? = null
    private var rsaPublic: PublicKey? = null
    private val secureRandom = SecureRandom()
    private val cipherMode:String by lazy { "$symmetricEncryption/$symmetricBlockMode/$symmetricPadding"}
    private val ivRequired:Int by lazy {
        if (symmetricBlockMode == "ECB") {
            0
        } else if (symmetricEncryption == "BLOWFISH") {
            8
        } else {
            16
        }
    }

    private val propertyBlockMode by lazy{
        if(symmetricBlockMode == KeyProperties.BLOCK_MODE_ECB){
            KeyProperties.BLOCK_MODE_ECB
        }else if(symmetricBlockMode == KeyProperties.BLOCK_MODE_CBC){
            KeyProperties.BLOCK_MODE_CBC
        }else if (symmetricBlockMode == KeyProperties.BLOCK_MODE_CTR){
            KeyProperties.BLOCK_MODE_CTR
        }else {
            KeyProperties.BLOCK_MODE_GCM
        }
    }

    private val propertyPadding by lazy {
        if(symmetricPadding == KeyProperties.ENCRYPTION_PADDING_NONE){
            KeyProperties.ENCRYPTION_PADDING_NONE
        }else if (symmetricPadding == KeyProperties.ENCRYPTION_PADDING_PKCS7){
            KeyProperties.ENCRYPTION_PADDING_PKCS7
        }else if (symmetricPadding == KeyProperties.ENCRYPTION_PADDING_RSA_OAEP){
            KeyProperties.ENCRYPTION_PADDING_RSA_OAEP
        }else {
            KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
        }
    }

    private var symmetricSalt32Bytes = ByteArray(32)

    companion object {
        val KEY_ALGORITHM_RSA = "RSA"

        val AES_CBC_PKCS5 = "AES/CBC/PKCS5Padding"
        val AES_GCM_NONE = "AES/GCM/NoPadding"
        val AES_CTR_PKCS5 = "AES/CTR/PKCS5Padding"
        val RSA_ECB_PKCS1 = "RSA/ECB/PKCS1Padding"
        val BLOWFISH_CTR_PKCS5 = "BLOWFISH/CTR/PKCS5Padding"
        val AES = "AES"
    }


    init {
        if (nameSpace.isEmpty()) {
            throw IllegalArgumentException("Need to specify a nameSpace")
        }

        preference = context.getSharedPreferences("secure_$nameSpace", Context.MODE_PRIVATE)

        initRsaKey()
        initSymmetricSalt()
    }

    protected fun finalize() {
        disposable.dispose()
    }

    fun initSymmetricSalt() {
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

    fun initRsaKey() {
        val rsaKeyName = "RSA_$nameSpace"
        val androidKeyStore = KeyStore.getInstance("AndroidKeyStore")
        androidKeyStore.load(null)
        if (androidKeyStore.containsAlias(rsaKeyName)) {
            rsaPrivate = (androidKeyStore.getEntry(rsaKeyName, null) as KeyStore.PrivateKeyEntry).privateKey
            if (rsaPrivate == null) {
                throw IllegalStateException("Failed to retrive RSA key RSA_$nameSpace from AndroidKeyStore, this should not happen.")
            }
            val cert = androidKeyStore.getCertificate(rsaKeyName)
            rsaPublic = cert.publicKey
            return
        }

        val kpg = KeyPairGenerator.getInstance(KEY_ALGORITHM_RSA, "AndroidKeyStore")
        val keySpec = KeyPairGeneratorSpec.Builder(context)
            .setAlias(rsaKeyName)
            .setKeyType(KEY_ALGORITHM_RSA)
            .setKeySize(3072)
            .setSubject(X500Principal("CN=$nameSpace"))
            .setSerialNumber(BigInteger.ONE)
            .setStartDate(Date(1970, 1, 1, 1, 1, 1))
            .setEndDate(Date(2100, 1, 1, 1, 1, 1))
            .build()
        kpg.initialize(keySpec)
        val pair = kpg.genKeyPair()
        rsaPrivate = pair.private
        rsaPublic = pair.public
    }

    fun digestPassCode(passcode: String) : ByteArray{
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
        if(ivRequired == 0){
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
            Pair(encTextBytes.sliceArray(IntRange(0, ivRequired - 1)),
                encTextBytes.sliceArray(IntRange(16, encTextBytes.size - 1)))
        }

        val skeySpec = SecretKeySpec(digestPassCode(passcode), symmetricEncryption)
        val cipher = Cipher.getInstance(cipherMode)
        if(ivRequired == 0){
            cipher.init(Cipher.DECRYPT_MODE, skeySpec)
        }else {
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, IvParameterSpec(pair.first))
        }

        return cipher.doFinal(pair.second)
    }


    @RequiresApi(Build.VERSION_CODES.M)
    fun encryptWithBiometrics(activity: FragmentActivity, clearTextBytes: ByteArray): Observable<Pair<ByteArray, ByteArray>?> {
        if (secretKey == null) {
            Toast.makeText(activity, "Run initBiometrics first", Toast.LENGTH_LONG).show()
            return Observable.error(IllegalStateException("Run initBiometrics first"))
        }
        val cipher = Cipher.getInstance(
            symmetricEncryption + "/"
                    + symmetricBlockMode + "/"
                    + symmetricPadding)
            .apply {
                init(Cipher.ENCRYPT_MODE, secretKey)
            }
        var cryptoObject = BiometricPrompt.CryptoObject(cipher)
        return RxBiometric
            .title("Encrypt")
            .description("Encrypt")
            .negativeButtonText("cancel")
            .negativeButtonListener(DialogInterface.OnClickListener { p0, p1 ->
            })
            .executor(ActivityCompat.getMainExecutor(activity))
            .build()
            .authenticate(activity, cryptoObject)
            .observeOn(AndroidSchedulers.mainThread())
            .map { authResult ->
                if (authResult.cryptoObject == null) {
                    return@map null
                } else {
                    val cipher = authResult.cryptoObject!!.cipher!!
                    val result = cipher.doFinal(clearTextBytes)
                    val iv = cipher.iv
                    return@map Pair(result, iv)
                }
            }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun decryptWithBiometrics(activity: FragmentActivity, encryptTextAndIv: Pair<ByteArray, ByteArray>): Observable<ByteArray?> {
        if (secretKey == null) {
            Toast.makeText(activity, "Run initBiometrics first", Toast.LENGTH_LONG).show()
            return Observable.error(IllegalStateException("Run initBiometrics first"))
        }
        val cipher = Cipher.getInstance(
            symmetricEncryption + "/"
                    + symmetricBlockMode + "/"
                    + symmetricPadding)
            .apply {
                init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(encryptTextAndIv.second))
            }
        var cryptoObject = BiometricPrompt.CryptoObject(cipher)
        return RxBiometric
            .title("Decrypt")
            .description("Decrypt")
            .negativeButtonText("cancel")
            .negativeButtonListener(DialogInterface.OnClickListener { p0, p1 ->
            })
            .executor(ActivityCompat.getMainExecutor(activity))
            .build()
            .authenticate(activity, cryptoObject)
            .observeOn(AndroidSchedulers.mainThread())
            .map { authResult ->
                if (authResult.cryptoObject == null) {
                    return@map null
                } else {
                    val cipherFromResult = authResult.cryptoObject!!.cipher!!
                    val result = cipherFromResult.doFinal(encryptTextAndIv.first)
                    return@map result
                }
            }
    }


    @RequiresApi(Build.VERSION_CODES.M)
    fun initBiometrics(acvitity: FragmentActivity) : Single<Boolean> {
        return RxPreconditions.canHandleBiometric(acvitity)
            .observeOn(AndroidSchedulers.mainThread())
            .map {
                if (!it) {
                    throw java.lang.IllegalStateException("No biometric support")
                }else{
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

                val builder = KeyGenParameterSpec.Builder(keyAlias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
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

}