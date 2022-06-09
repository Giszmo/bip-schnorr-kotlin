package de.leowandersleb.lib_bip_schnorr_kotlin

import org.spongycastle.jce.ECNamedCurveTable
import org.spongycastle.util.encoders.Hex
import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPublicKeySpec
import kotlin.random.Random

object Schnorr {
    private val p = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    private val n = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    private val G = arrayOf(
        BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
        BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    )
    private val TWO = BigInteger.valueOf(2)
    private val THREE = BigInteger.valueOf(3)
    private val hexArray = "0123456789ABCDEF".toCharArray()

    private fun pointAdd(p1: Array<BigInteger>?, p2: Array<BigInteger>?): Array<BigInteger>? {
        if (p1 == null || p1.size != 2) return p2
        if (p2 == null || p2.size != 2) return p1
        if (p1[0].compareTo(p2[0]) == 0 && p1[1].compareTo(p2[1]) != 0) return null
        val lam: BigInteger = if (p1[0].compareTo(p2[0]) == 0 && p1[1].compareTo(p2[1]) == 0) {
            THREE
                .multiply(p1[0])
                .multiply(p1[0])
                .multiply(TWO.multiply(p1[1]).modPow(p.subtract(TWO), p))
                .mod(p)
        } else {
            p2[1]
                .subtract(p1[1])
                .multiply(p2[0].subtract(p1[0]).modPow(p.subtract(TWO), p))
                .mod(p)
        }
        val x3 = lam.multiply(lam).subtract(p1[0]).subtract(p2[0]).mod(p)
        return arrayOf(x3, lam.multiply(p1[0].subtract(x3)).subtract(p1[1]).mod(p))
    }

    private fun pointMul(P: Array<BigInteger>?, n: BigInteger): Array<BigInteger>? {
        var varP = P
        var R: Array<BigInteger>? = null
        for (i in 0..255) {
            if (BigInteger.ONE.compareTo(n.shiftRight(i).and(BigInteger.ONE)) == 0)
                R = pointAdd(R, varP)
            varP = pointAdd(varP, varP)
        }
        return R
    }

    private fun jacobi(x: BigInteger): BigInteger =
        x.modPow(p.subtract(BigInteger.ONE).divide(TWO), p)

    private fun pointFromBytes(b: ByteArray): Array<BigInteger>? {
        if (b[0] != 2.toByte() && b[0] != 3.toByte()) return null
        val odd = if (b[0] == 3.toByte()) BigInteger.ONE else BigInteger.ZERO
        val x = toBigInteger(b, 1, 32)
        val ySq = x.modPow(THREE, p).add(BigInteger.valueOf(7)).mod(p)
        val y0 = ySq.modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p)
        if (ySq.compareTo(y0.modPow(TWO, p)) != 0) return null
        val y = if (y0.and(BigInteger.ONE).compareTo(odd) != 0) p.subtract(y0) else y0
        return arrayOf(x, y)
    }

    private fun to32BytesData(num: BigInteger): ByteArray {
        var hexNum = num.toString(16)
        if (hexNum.length < 64) {
            val sb = StringBuilder()
            for (i in 0 until 64 - hexNum.length) sb.append("0")
            hexNum = sb.append(hexNum).toString()
        }
        return Hex.decode(hexNum)
    }

    private fun toBigInteger(data: ByteArray, startPos: Int, len: Int) =
        BigInteger(bytesToHex(data, startPos, len), 16)

    private fun toBigInteger(data: ByteArray) = BigInteger(bytesToHex(data), 16)

    private fun bytesFromPoint(point: Array<BigInteger>?): ByteArray {
        val res = ByteArray(33)
        res[0] =
            if (BigInteger.ONE.compareTo(point!![1].and(BigInteger.ONE)) == 0) 0x03.toByte() else 0x02.toByte()
        System.arraycopy(to32BytesData(point[0]), 0, res, 1, 32)
        return res
    }

    fun sign(msg: ByteArray, seckey: BigInteger): ByteArray {
        if (msg.size != 32) throw RuntimeException("The message must be a 32-byte array.")
        if ((BigInteger.ZERO > seckey) || (seckey > n.subtract(BigInteger.ONE)))
            throw RuntimeException("The secret key must be an integer in the range 1..n-1.")
        val resultData = ByteArray(32 + msg.size)
        System.arraycopy(to32BytesData(seckey), 0, resultData, 0, 32)
        System.arraycopy(msg, 0, resultData, 32, msg.size)
        val k0 = toBigInteger(sha256(resultData)).mod(n)
        if (BigInteger.ZERO.compareTo(k0) == 0) throw RuntimeException("Failure. This happens only with negligible probability.")
        val R = pointMul(G, k0)
        val k = if (BigInteger.ONE.compareTo(jacobi(R!![1])) != 0) n.subtract(k0) else k0
        val R0Bytes = to32BytesData(R[0])
        var eData = ByteArray(32 + 33 + 32)
        System.arraycopy(R0Bytes, 0, eData, 0, 32)
        System.arraycopy(bytesFromPoint(pointMul(G, seckey)), 0, eData, 32, 33)
        System.arraycopy(msg, 0, eData, 65, 32)
        eData = sha256(eData)
        val e = toBigInteger(eData).mod(n)
        val finalData = ByteArray(64)
        System.arraycopy(R0Bytes, 0, finalData, 0, 32)
        System.arraycopy(to32BytesData(e.multiply(seckey).add(k).mod(n)), 0, finalData, 32, 32)
        return finalData
    }

    fun verify(msg: ByteArray, pubKey: ByteArray, sig: ByteArray): Boolean {
        if (msg.size != 32) throw RuntimeException("The message must be a 32-byte array.")
        if (sig.size != 64) throw RuntimeException("The signature must be a 64-byte array.")
        return when (pubKey.size) {
            33 -> internalVerify(msg, arrayOf(2.toByte()).toByteArray() + pubKey, sig)
            32 -> internalVerify(msg, arrayOf(2.toByte()).toByteArray() + pubKey, sig)
                || internalVerify(msg, arrayOf(2.toByte()).toByteArray() + pubKey, sig)
            else -> throw RuntimeException("The public key must be a 32 or 33-byte array.")
        }
    }

    // TODO: This is expenesive! How can we speed this up?
    private fun internalVerify(msg: ByteArray, pubKey: ByteArray, sig: ByteArray): Boolean {
        val P = pointFromBytes(pubKey) ?: return false
        val r = toBigInteger(sig, 0, 32)
        val s = toBigInteger(sig, 32, 32)
        return if (r >= p || s >= n) false else {
            var eData = ByteArray(32 + 33 + 32)
            System.arraycopy(sig, 0, eData, 0, 32)
            System.arraycopy(bytesFromPoint(P), 0, eData, 32, 33)
            System.arraycopy(msg, 0, eData, 65, 32)
            eData = sha256(eData)
            val e = toBigInteger(eData).mod(n)
            val R = pointAdd(pointMul(G, s), pointMul(P, n.subtract(e)))
            !(R == null || BigInteger.ONE.compareTo(jacobi(R[1])) != 0 || r.compareTo(R[0]) != 0)
        }
    }

    fun hexStringToByteArray(s: String): ByteArray {
        check(s.length % 2 == 0)
        return s
            .chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }

    fun bytesToHex(bytes: ByteArray): String {
        val hexChars = CharArray(bytes.size * 2)
        for (j in bytes.indices) {
            val v: Int = bytes[j].toInt() and 0xFF
            hexChars[j * 2] = hexArray[v ushr 4]
            hexChars[j * 2 + 1] = hexArray[v and 0x0F]
        }
        return String(hexChars)
    }

    private fun bytesToHex(bytes: ByteArray, startPos: Int, len: Int): String {
        val hexChars = CharArray(len * 2)
        var j = 0
        var i = startPos
        while (j < len) {
            val v: Int = bytes[i].toInt() and 0xFF
            hexChars[j * 2] = hexArray[v ushr 4]
            hexChars[j * 2 + 1] = hexArray[v and 0x0F]
            j++
            i++
        }
        return String(hexChars)
    }

    fun getPrivateKey() = Random.Default.nextBytes(32)

    fun getPubKey(pk: ByteArray): ByteArray {
        val spec = ECNamedCurveTable.getParameterSpec("secp256k1")
        val pointQ = spec.g.multiply(BigInteger(1, pk))
        return pointQ.getEncoded(false).copyOfRange(1, 33)
    }

    fun sha256(input: ByteArray?): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(input)
}