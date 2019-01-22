package org.ksc91u.sample

import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
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


        if(Build.VERSION.SDK_INT > Build.VERSION_CODES.M) {
            preference.initBiometrics(this).flatMap {
                return@flatMap preference.putString("main_key", "hello world", this)
            }.flatMap {
             return@flatMap preference.getString("main_key", this)
            }.subscribeBy(onSuccess = {
                println(">>> put ok")
                println(">>> get $it")
            })

        }

        var textLtn = """
〔即時新聞／綜合報導〕新北市蘆洲區林姓男子，僅僅因為兒子買肉圓沒加辣，竟直接出手痛毆，連上來勸阻的妻子被狠狠勒脖，
林男目前已在新北市蘆洲分局集賢派出所公開道歉。
42歲的林姓男子戴著口罩在派出所現身，表示由於酒後失控對老婆小孩造成了傷害，必須要在此致歉，接著就鞠躬道歉。
林男說，他也要對浪費社會資源道歉、對造成警方和媒體的困擾道歉、對社區鄰居這幾天出入不便道歉、對岳父岳母道歉。
        """.trimIndent()
        textTv.text = textLtn

        btnWrite.setOnClickListener {
            if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val string = "test 123 " + Random().nextInt()%100
                preference.putString("test", string,this)
                    .subscribeBy(onSuccess = {
                        Toast.makeText(this, "Write $string success", Toast.LENGTH_LONG).show()
                    })
            }
        }

        btnRead.setOnClickListener{
            if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                preference.getString("test",this)
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
                    preference.initBiometrics(this)
                        .flatMap {
                            return@flatMap preference.decryptWithBiometrics(this@MainActivity, pairNotNull)
                        }.subscribeBy(onSuccess = {
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
    }
}
