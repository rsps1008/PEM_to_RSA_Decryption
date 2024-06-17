package rsa_decode;

import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.security.PrivateKey;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

import java.io.Reader;
import javax.crypto.Cipher;

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public class rsa_decode_fun {
	
	public static String HelloWorld = "KkWm0U5/aW5Ag03TZUAcc9EHAnRPXwNXS/VqseDoGeswKCSBfNq2MOqn51cylG09FuR+ShXKicjgcHeqCn2yKvclLkVygHhOG5vckZ7ZZDhF8KeknHTDISQHtfdl/n6OnnqXm9dz7OW259W3k3T0iBTHle7dWol/xiRAMM1jBSOFXmMMauf7NHII7+euOVC27pZplO3HOMEIArkqQ2sHzezS8hsz08I09FXH9YofkNOrf4uBEajirnPK1gmqnQ1p87os3NtIib+3rD7jtsAzsXRNEMCwFZSdCMkUKY2asn4pZQwwwfAnR3OU9SDDfporXE0BN0eHKbue02mEyz7gyVHCnqIYZaSG9goSFvrzQAIY9XXQMK1XMGKX5znfUGfZxYYgw8Q2U7SfS3IaAHpQQnVWgpAkK8Gv0eBFgs9WM3AQ44Lqv2fWNtp+eflsfSdW6T7SodMVefmILLztYeUWFUsKNNSyjeQq47QQsE+a/VRaUgZfOJktmnrr51kbJsWqA2vOx9DSrqrtyAXgslWwbSn1AeCitW+0nHZ66i70FUpSfEnywaXJkeyjkc35L4NfgVPZWalnfDDWnnNommn+Su5sxuxRPOGP9KEvR7DNHW7vOAICCC1yZfpZ7yn8QU/6m6gBW73OTqnwd2njUpMn88OgHEZA9fqRQohd21feUKU=";

	
	public static SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public static void main(String[] args) {
        String result = decode(HelloWorld, "E:\\Google雲端硬碟\\JWT_Project\\Lib\\測試用公私鑰\\RP(JWT Payload加密)\\private_key.pem");
        System.out.println(result);
    }
    
    private static PrivateKey getPrivateKey(String privateKey) throws Exception {
        Reader privateKeyReader = new StringReader(privateKey);
        PEMParser privatePemParser = new PEMParser(privateKeyReader);
        Object privateObject = privatePemParser.readObject();
        if (privateObject instanceof PEMKeyPair) {
            PEMKeyPair pemKeyPair = (PEMKeyPair) privateObject;
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            PrivateKey privKey = converter.getPrivateKey(pemKeyPair.getPrivateKeyInfo());
            return privKey;
        }
        return null;
    }

    public static String decode(String str, String privateKeyPath) {
        try {
            String privateKeyPEM = null;
            String str_decode = null;

        	try {
	            // Read the private key file.
	            privateKeyPEM = new String(Files.readAllBytes(Paths.get(privateKeyPath)));
        	} catch (Exception e) {
        		throw new RuntimeException("Private Key Read Error");
        	}
        	try {
	            // Processing a PKCS#1 private key.
	            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
	            rsa.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKeyPEM));
	            byte[] utf8 = rsa.doFinal(Base64.getDecoder().decode(str));
	            str_decode = new String(utf8, "UTF-8");
				return str_decode;
        	} catch (Exception e) {
        		throw new RuntimeException("RSA私鑰解密失敗" + e);
        	}
        } catch (Exception e) {
            String currentTime = sdf.format(new Date());
            return String.format("[%s] %s",currentTime, e.getMessage());
        }
    }
}