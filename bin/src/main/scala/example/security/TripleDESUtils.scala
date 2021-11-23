package example.security;

import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;

object TripleDESUtils {

  val digestName = "md5";

  @throws (classOf[Exception])
  def generateKey(n :Int) :SecretKey = {
      val keyGenerator :KeyGenerator = KeyGenerator.getInstance("AES")
      keyGenerator.init(n)
      return keyGenerator.generateKey()
  }

  @throws (classOf[Exception])
  def generateSalt(n: Int): String = {
     val key = generateKey(n);
     return java.util.Base64.getEncoder().encodeToString(key.getEncoded());
  }

  @throws(classOf[Exception])
  def setupSecretKey(digestPassword: String): SecretKey = {
      val md = MessageDigest.getInstance(digestName);
      val digestOfPassword = md.digest(digestPassword.getBytes());
      val keyBytes = Arrays.copyOf(digestOfPassword, 24);
      for ( j <- 0 to 8; k <- 16 until 24) {
          keyBytes(+k) = keyBytes(+j);
      }

      return new SecretKeySpec(keyBytes, "DESede");
  }

  @throws(classOf[Exception])
  def setupCipher(optMode: Int, digestPassword: String): Cipher = {
    val key = setupSecretKey(digestPassword);
    val iv = new IvParameterSpec(new Array[Byte](8));
    val cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
    cipher.init(optMode, key, iv);
    return cipher;
  }

  @throws(classOf[Exception])
  def encrypt(message: String, digestPassword: String): Array[Byte] = {
      val cipher = setupCipher(Cipher.ENCRYPT_MODE, digestPassword);

      val plainTextBytes = message.getBytes()
      val cipherText = cipher.doFinal(plainTextBytes);

      return cipherText;
  }

}
