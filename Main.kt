package com.gp.kotlin.main

import com.gp.kotlin.main.crypto.Crypto
import java.util.Base64

fun main(args: Array<String>) {
	val map = Crypto("ccc").encrypt("this is a password")
	val salt = map["salt"]
	val iv = map["iv"]
	val encrypted = map["encrypted"]
	println("salt: ${String(salt!!)}")
	println("iv: ${String(iv!!)}")
	println("encrypted: ${String(encrypted!!)}")
	println("Encrypted successfully!")
	println(Crypto("ccc").decrypt(hashMapOf("salt" to salt, "iv" to iv, "encrypted" to encrypted)))
}