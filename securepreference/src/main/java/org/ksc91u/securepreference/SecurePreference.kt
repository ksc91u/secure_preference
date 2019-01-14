package org.ksc91u.securepreference

import android.content.Context
import android.content.SharedPreferences
import android.security.KeyPairGeneratorSpec
import android.util.Base64
import java.math.BigInteger
import java.security.*
import java.util.*
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.security.auth.x500.X500Principal

class SecurePreference(
    val nameSpace: String,
    val context: Context,
    val symmetricEncryption: String = "AES",
    val symmetricPadding: String = "NoPadding",
    val symmetricBlockMode: String = "GCM",
    val keyHashAlgorithm: String = "SHA-256",
    val asymmetricEncryption: String = "RSA"
) {

    lateinit var preference: SharedPreferences

    var secretKey: SecretKey? = null
    var rsaPrivate: PrivateKey? = null
    var rsaPublic: PublicKey? = null
    val secureRandom = SecureRandom()
    val cipherMode:String by lazy { "$symmetricEncryption/$symmetricBlockMode/$symmetricPadding"}
    val ivRequired:Int by lazy {
        if (symmetricBlockMode == "ECB") {
            0
        } else if (symmetricEncryption == "BLOWFISH") {
            8
        } else {
            16
        }
    }

    var symmetricSalt32Bytes = ByteArray(32)

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
        var bytes = passcode.toByteArray() + symmetricSalt32Bytes
        var digest = MessageDigest.getInstance(keyHashAlgorithm)
        for(i in 0 .. 1000) {
            digest.update(bytes)
            bytes = digest.digest() + symmetricSalt32Bytes
        }
        return digest.digest()
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

}