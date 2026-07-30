package com.foundationdevices.passport.wdk.quantumlink

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal class SecureIdentityStore(private val context: Context) {
  companion object {
    private const val KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "passport_quantumlink_identity_v1"
    private const val PREFS = "passport_quantumlink_secure"
    private const val IDENTITY = "identity_ciphertext"
    private const val VERSION: Byte = 1
  }

  fun load(): ByteArray? {
    val encoded = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
      .getString(IDENTITY, null) ?: return null
    val blob = Base64.decode(encoded, Base64.NO_WRAP)
    require(blob.size > 14 && blob[0] == VERSION) { "Invalid encrypted identity" }
    val ivLength = blob[1].toInt() and 0xff
    require(ivLength in 12..16 && blob.size > 2 + ivLength) { "Invalid identity nonce" }
    val iv = blob.copyOfRange(2, 2 + ivLength)
    val ciphertext = blob.copyOfRange(2 + ivLength, blob.size)
    return Cipher.getInstance("AES/GCM/NoPadding").run {
      init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))
      doFinal(ciphertext)
    }
  }

  fun save(identity: ByteArray) {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
      init(Cipher.ENCRYPT_MODE, getOrCreateKey())
    }
    val ciphertext = cipher.doFinal(identity)
    val blob = byteArrayOf(VERSION, cipher.iv.size.toByte()) + cipher.iv + ciphertext
    context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
      .edit()
      .putString(IDENTITY, Base64.encodeToString(blob, Base64.NO_WRAP))
      .apply()
  }

  private fun getOrCreateKey(): SecretKey {
    val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
    (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

    return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).run {
      init(
        KeyGenParameterSpec.Builder(
          KEY_ALIAS,
          KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
          .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
          .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
          .setKeySize(256)
          .setRandomizedEncryptionRequired(true)
          .build()
      )
      generateKey()
    }
  }
}
