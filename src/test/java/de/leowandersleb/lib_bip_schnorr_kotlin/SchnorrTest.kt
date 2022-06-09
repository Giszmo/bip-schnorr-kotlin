package de.leowandersleb.lib_bip_schnorr_kotlin

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvFileSource
import org.spongycastle.util.encoders.Hex
import java.math.BigInteger
import java.util.*

class SchnorrSigTest {
    @ParameterizedTest
    @CsvFileSource(resources = ["/test_schnorr_data_with_priv_key.txt"], numLinesToSkip = 0)
    fun testGetPublicKey(id: String, secKeyHex: String, pubKeyHex: String, msgHex: String, sigHex: String, resultString: String, comment: String?) {
        val pubKeyActual = Schnorr.getPubKey(Hex.decode(secKeyHex))
        assertEquals(pubKeyHex, Schnorr.bytesToHex(pubKeyActual), "Failed reproducing the pubKey")
    }

    @ParameterizedTest
    @CsvFileSource(resources = ["/test_schnorr_data_with_priv_key.txt"], numLinesToSkip = 0)
    fun testSignContent(id: String, secKeyHex: String, pubKeyHex: String, msgHex: String, sigHex: String, resultString: String, comment: String?) {
        val secKeyNum = BigInteger(secKeyHex, 16)
        val sigActual = Schnorr.sign(Hex.decode(msgHex), secKeyNum)
        assertEquals(sigHex.lowercase(Locale.US), String(Hex.encode(sigActual)), "Failed signing test $id (${comment})")
    }

    @ParameterizedTest
    @CsvFileSource(resources = ["/test_schnorr_data_with_priv_key.txt", "/test_schnorr_data_no_priv_key.txt"], numLinesToSkip = 0)
    fun testVerify(id: String, secKeyHex: String?, pubKeyHex: String, msgHex: String, sigHex: String, resultString: String, comment: String?) {
        val verifyExpected = resultString == "TRUE"
        val verifyActual = Schnorr.verify(Hex.decode(msgHex), Hex.decode(pubKeyHex), Hex.decode(sigHex))
        assertEquals(verifyExpected, verifyActual, "Failed verification test $id ($comment)")
    }
}

class SchnorrKeysTest {
    @Test
    fun testKeyPair() {
        val secKey = "dca4f4bf2883e4502200d7831ad891ace8c895709e9f09c9f9692632ae36c482".uppercase(Locale.US)
        val pubKey = "ce16d1d2fabca7184d1502c147d5e029e88e63f8ff31ebfe3dbc9677819061cf".uppercase(Locale.US)
        testKeys(secKey, pubKey)
    }

    @Test
    fun testSecKey() {
        repeat(100) {
            val secKey = Schnorr.getPrivateKey()
            val secKeyHex = Schnorr.bytesToHex(secKey)
            val pubKey = Schnorr.getPubKey(secKey)
            val pubKeyHex = Schnorr.bytesToHex(pubKey)
            testKeys(secKeyHex, pubKeyHex)
        }
    }

    private fun testKeys(secKeyHex: String, pubKeyHex: String) {
        val secKeyBytes = Hex.decode(secKeyHex)
        val pubKeyResult = Schnorr.getPubKey(secKeyBytes)
        val pubKeyResultHex = Schnorr.bytesToHex(pubKeyResult)
        assertEquals(pubKeyHex, pubKeyResultHex)
    }
}
