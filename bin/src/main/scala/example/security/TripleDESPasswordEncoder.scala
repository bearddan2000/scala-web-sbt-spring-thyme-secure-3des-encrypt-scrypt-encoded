package example.security;

import javax.xml.bind.DatatypeConverter;

import org.springframework.security.crypto.password.PasswordEncoder;

class TripleDESPasswordEncoder
  extends org.springframework.security.crypto.scrypt.SCryptPasswordEncoder
  with PasswordEncoder {

    val digestPassword = TripleDESUtils.generateSalt(256);

    override def encode(rawPassword: CharSequence): String = {
      try {
        val plainText = rawPassword.toString();
        val rsaText = TripleDESUtils.encrypt(plainText, digestPassword);
        return super.encode(DatatypeConverter.printHexBinary(rsaText));
      } catch{
        case e: Exception => {}
      }
      return super.encode(rawPassword);
    }

    override def matches(rawPassword: CharSequence, encodedPassword: String): Boolean =
    {
     try {
        val plainText = rawPassword.toString();
        val rsaText = TripleDESUtils.encrypt(plainText, digestPassword);
        val plain = DatatypeConverter.printHexBinary(rsaText);
       return super.matches(plain, encodedPassword);
       } catch{
         case e: Exception => {}
       }
     return false;
    }
}
