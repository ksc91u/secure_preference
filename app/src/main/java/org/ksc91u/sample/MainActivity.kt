package org.ksc91u.sample

import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.FragmentManager
import io.reactivex.rxkotlin.subscribeBy
import kotlinx.android.synthetic.main.activity_main.*
import org.ksc91u.securepreference.SecurePreference
import java.util.*

class MainActivity : AppCompatActivity() {

    var pair: Pair<ByteArray, ByteArray>? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val preference = SecurePreference(
            "main",
            this
        )


        preference.initBiometrics()
        /*
        preference.putString("main_key", "hello world").flatMap {
            return@flatMap preference.getString("main_key")
        }.subscribeBy(onSuccess = {
            println(">>> put ok")
            println(">>> get $it")
        })*/


        var textLtn = """
示範將 session token 加密過後存到 Shared Preference, 必須經過指紋驗證才能解密拿到 token。session token 則可以用來免密碼登入 server。
        """.trimIndent()
        textTv.text = textLtn

        btnWrite.setOnClickListener {
            if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val string = "test 123 " + Random().nextInt() % 100
                preference.putString("test", string)
                    .subscribeBy(onSuccess = {
                        Toast.makeText(this, "Write $string success", Toast.LENGTH_LONG).show()
                    })
            }
        }

        btnRead.setOnClickListener {
            if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                preference.getString("test")
                    .subscribeBy(onSuccess = {
                        Toast.makeText(this, "Read $it success", Toast.LENGTH_LONG).show()
                    })
            }
        }

        btnDecrypt.setOnClickListener {
            if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val preference = SecurePreference(
                    "xx1c",
                    this,
                    symmetricPadding = "PKCS7Padding",
                    symmetricBlockMode = "CBC"
                )
                pair?.let { pairNotNull ->
                    preference.initBiometrics()
                    preference.decryptWithBiometrics(pairNotNull).subscribeBy(onSuccess = {
                            println(">>>> onsuccess")
                            textTv.text = String(it)
                        }, onError = {
                            println(">>>> onerror")
                            Toast.makeText(this@MainActivity, it.localizedMessage, Toast.LENGTH_LONG).show()
                        })
                }

            }
        }

        btnEncrypt.setOnClickListener {
            if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val preference = SecurePreference(
                    "xx1c",
                    this,
                    symmetricPadding = "PKCS7Padding",
                    symmetricBlockMode = "CBC"
                )
                preference.initBiometrics()
                preference.encryptWithBiometrics(textLtn.toByteArray()).subscribeBy(onSuccess = {
                        pair = it
                        textTv.text = Base64.encodeToString(it.first, Base64.URL_SAFE)
                    }, onError = {
                        supportFragmentManager.removeBiometricFragments()
                        Toast.makeText(this@MainActivity, it.localizedMessage, Toast.LENGTH_LONG).show()
                    })
            }
        }
    }

}

fun FragmentManager.removeBiometricFragments() {
    findFragmentByTag("FingerprintDialogFragment")?.let {
        (it as DialogFragment).dismiss()
    }
    findFragmentByTag("FingerprintHelperFragment")?.let {
        beginTransaction().remove(it).commitNow()
    }
    findFragmentByTag("BiometricFragment")?.let {
        beginTransaction().remove(it).commitNow()
    }
}
