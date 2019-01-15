package org.ksc91u.sample

import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import io.reactivex.rxkotlin.subscribeBy
import kotlinx.android.synthetic.main.activity_main.*
import org.ksc91u.securepreference.SecurePreference

class MainActivity : AppCompatActivity() {

    var pair: Pair<ByteArray, ByteArray>? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        var textLtn = """
〔即時新聞／綜合報導〕新北市蘆洲區林姓男子，僅僅因為兒子買肉圓沒加辣，竟直接出手痛毆，連上來勸阻的妻子被狠狠勒脖，
林男目前已在新北市蘆洲分局集賢派出所公開道歉。
42歲的林姓男子戴著口罩在派出所現身，表示由於酒後失控對老婆小孩造成了傷害，必須要在此致歉，接著就鞠躬道歉。
林男說，他也要對浪費社會資源道歉、對造成警方和媒體的困擾道歉、對社區鄰居這幾天出入不便道歉、對岳父岳母道歉。
        """.trimIndent()
        textTv.text = textLtn

        btnDecrypt.setOnClickListener {
            if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val preference = SecurePreference(
                    "xx1c",
                    this,
                    symmetricPadding = "PKCS7Padding",
                    symmetricBlockMode = "CBC"
                )
                pair?.let { pairNotNull ->
                    preference.initBiometrics(this)
                        .flatMap {
                            return@flatMap preference.decryptWithBiometrics(this@MainActivity, pairNotNull)
                        }.subscribeBy(onSuccess = {
                            textTv.text = String(it)
                        }, onError = {
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
                preference.initBiometrics(this)
                    .flatMap {
                        return@flatMap preference.encryptWithBiometrics(
                            this@MainActivity,
                            textLtn.toByteArray()
                        )
                    }.subscribeBy(onSuccess = {
                        pair = it
                        textTv.text = Base64.encodeToString(it.first, Base64.URL_SAFE)
                    }, onError = {
                        Toast.makeText(this@MainActivity, it.localizedMessage, Toast.LENGTH_LONG).show()
                    })
            }
        }

        var modes = arrayOf("GCM")
        modes.forEach {
            try {
                val preference = SecurePreference(
                    "xx1b",
                    this,
                    symmetricPadding = "NoPadding",
                    symmetricBlockMode = it
                )
                val bytes = preference.encryptWithPasscode("password", textLtn.toByteArray())
                val decrypt = preference.decryptWithPasscode("password", bytes)
                println(">>>> $it" + String(decrypt))
            } catch (e: Exception) {
                println(">>>> $it failed")
                println(">>>> ${e.localizedMessage}")
            }
        }

    }
}
