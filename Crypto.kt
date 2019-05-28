package com.gp.kotlin.main.crypto

import java.security.SecureRandom
import javax.crypto.spec.PBEKeySpec
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.Cipher
import java.util.HashMap

class Crypto(val password: String = "p@\$\$w0rd") {

	val random = SecureRandom()
	val salt = ByteArray(256)

	init {
		// generate salt
		random.nextBytes(salt)
	}


	fun encrypt(dataToEncrypt: String): HashMap<String, ByteArray> {

		val map = HashMap<String, ByteArray>()

		// generate key with password and salt
		val pbKeySpec = PBEKeySpec(password.toCharArray(), salt, 1324, 256)
		val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
		val keyBytes = secretKeyFactory.generateSecret(pbKeySpec).encoded
		val keySpec = SecretKeySpec(keyBytes, "AES")

		// add vector
		val ivRandom = SecureRandom()
		val iv = ByteArray(16)
		ivRandom.nextBytes(iv)
		val ivSpec = IvParameterSpec(iv)

		// specify cipher block chaining mode
		val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
		val encrypted = cipher.doFinal(dataToEncrypt.toByteArray())

		// save each item on sharedpreference to retrieve decrypted data
		map["iv"] = iv
		map["salt"] = salt
		map["encrypted"] = encrypted

		return map
	}

	fun decrypt(map: HashMap<String, ByteArray>): String {
		val salt = map["salt"]
		val iv = map["iv"]
		val encrypted = map["encrypted"]

		// regenerate key from password map's salt
		val pbKeySpec = PBEKeySpec(password.toCharArray(), salt, 1324, 256)
		val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
		val keyBytes = secretKeyFactory.generateSecret(pbKeySpec).encoded
		val keySpec = SecretKeySpec(keyBytes, "AES")

		// regenerate vector from password map's iv
		val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
		val ivSpec = IvParameterSpec(iv)
		cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)

		cipher.doFinal(encrypted).let {
			return String(it, Charsets.UTF_8)
		}
	}
}