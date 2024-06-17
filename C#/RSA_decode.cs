using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.OpenSsl;
using System.Security.Cryptography;
using System.Diagnostics;


namespace rsa_decode_fun
{
    public class rsa_decode_class
    {
        public static string ConvertPemToXml(string pem)
        {
            PemReader pemReader = new PemReader(new StringReader(pem));
            AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
            RsaPrivateCrtKeyParameters privateKeyParams = (RsaPrivateCrtKeyParameters)keyPair.Private;

            RSAParameters rsaParams = new RSAParameters
            {
                Modulus = privateKeyParams.Modulus.ToByteArrayUnsigned(),
                Exponent = privateKeyParams.PublicExponent.ToByteArrayUnsigned(),
                D = privateKeyParams.Exponent.ToByteArrayUnsigned(),
                P = privateKeyParams.P.ToByteArrayUnsigned(),
                Q = privateKeyParams.Q.ToByteArrayUnsigned(),
                DP = privateKeyParams.DP.ToByteArrayUnsigned(),
                DQ = privateKeyParams.DQ.ToByteArrayUnsigned(),
                InverseQ = privateKeyParams.QInv.ToByteArrayUnsigned()
            };

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);
                return rsa.ToXmlString(true);
            }
        }
        
        public static string DecryptRSA(string encryptedText, string privateKey)
        {
            try
            {
                // Convert the PEM-formatted private key to XML format
                string privateKeyXml = ConvertPemToXml(privateKey);

                // Create an RSA decryption utility.
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(privateKeyXml);

                    // Decrypt
                    byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
                    byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, false);
                    string decryptedText = Encoding.UTF8.GetString(decryptedBytes);

                    return decryptedText;
                }
            }
            catch (Exception ex)
            {
                throw new Exception("RSA private key decryption failed");
            }
        }

        static string ReadFile(string filePath, string kindofkey)
        {
            try
            {
                // Read file contents
                string content = File.ReadAllText(filePath);
                return content;
            }
            catch (Exception ex)
            {
                throw new Exception(kindofkey + " Read Error");
            }
        }

        static void Main(string[] args)
        {
            string HelloWorld = "KkWm0U5/aW5Ag03TZUAcc9EHAnRPXwNXS/VqseDoGeswKCSBfNq2MOqn51cylG09FuR+ShXKicjgcHeqCn2yKvclLkVygHhOG5vckZ7ZZDhF8KeknHTDISQHtfdl/n6OnnqXm9dz7OW259W3k3T0iBTHle7dWol/xiRAMM1jBSOFXmMMauf7NHII7+euOVC27pZplO3HOMEIArkqQ2sHzezS8hsz08I09FXH9YofkNOrf4uBEajirnPK1gmqnQ1p87os3NtIib+3rD7jtsAzsXRNEMCwFZSdCMkUKY2asn4pZQwwwfAnR3OU9SDDfporXE0BN0eHKbue02mEyz7gyVHCnqIYZaSG9goSFvrzQAIY9XXQMK1XMGKX5znfUGfZxYYgw8Q2U7SfS3IaAHpQQnVWgpAkK8Gv0eBFgs9WM3AQ44Lqv2fWNtp+eflsfSdW6T7SodMVefmILLztYeUWFUsKNNSyjeQq47QQsE+a/VRaUgZfOJktmnrr51kbJsWqA2vOx9DSrqrtyAXgslWwbSn1AeCitW+0nHZ66i70FUpSfEnywaXJkeyjkc35L4NfgVPZWalnfDDWnnNommn+Su5sxuxRPOGP9KEvR7DNHW7vOAICCC1yZfpZ7yn8QU/6m6gBW73OTqnwd2njUpMn88OgHEZA9fqRQohd21feUKU=";
            jwt_decode_class decoder = new jwt_decode_class();
            string result = decoder.decode(HelloWorld, "E:\\Google雲端硬碟\\JWT_Project\\Lib\\測試用公私鑰\\RP(JWT Payload加密)\\private_key.pem");
            Console.WriteLine(result);
            Console.ReadLine();
        }

        public string decode(string str, string privateKeyPath)
        {
            try
            {
                string privateKey = ReadFile(privateKeyPath, "Private Key");
                string payload = DecryptRSA(str, privateKey);

                return payload;
            }
            catch (Exception e)
            {
                string message = string.Format("[{0}] RSA private key decryption failed: {1}", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), e.Message);
                return message;
            }
        }


        private static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+');
            output = output.Replace('_', '/');
            switch (output.Length % 4)
            {
                case 0: break;
                case 2: output += "=="; break;
                case 3: output += "="; break;
                default: throw new System.Exception("Invalid length of the input Base64Url string.");
            }
            var converted = Convert.FromBase64String(output);
            return converted;
        }
    }
}
