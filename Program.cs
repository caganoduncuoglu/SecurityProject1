using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Serialization;

namespace SecurityProject1
{
    public class RSAEncryption
    {
        private static RSA csp = RSA.Create(1024);
        private RSAParameters _privateKey;
        private RSAParameters _publicKey;
        
        public RSAEncryption()
        {
            _privateKey = csp.ExportParameters(true);
            _publicKey = csp.ExportParameters(false);
        }

        public RSA GetCSP()
        {
            return csp;
        }
        
        public string GetPublicKey()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw,_publicKey);
            return sw.ToString();
        }
        
        public string GetPrivateKey() // May not be shown
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw,_privateKey);
            return sw.ToString();
        }
    }
    
    
    
    internal class Program
    {
        public static void Main(string[] args)
        {
            RSAEncryption rsa = new RSAEncryption();
            Console.WriteLine($"Public Key:  {rsa.GetPublicKey()} \n");
            Console.WriteLine($"Private Key:  {rsa.GetPrivateKey()} \n");

            AesCryptoServiceProvider k1 = new AesCryptoServiceProvider();
            k1.KeySize = 128;
            k1.GenerateKey();
            byte[] key1Generated = k1.Key;
            String Key1 = Convert.ToBase64String(key1Generated);
            
            AesCryptoServiceProvider k2 = new AesCryptoServiceProvider();
            k2.KeySize = 256;
            k2.GenerateKey();
            byte[] key2Generated = k2.Key;
            String Key2 = Convert.ToBase64String(key2Generated);
            
            Console.WriteLine("Symmetric Key1: " + Key1);
            Console.WriteLine("Symmetric Key2: " + Key2);
            
            // RSA Encryption 
            var encryptedK1 = rsa.GetCSP().Encrypt(key1Generated, RSAEncryptionPadding.Pkcs1);
            var encryptedK2 = rsa.GetCSP().Encrypt(key2Generated, RSAEncryptionPadding.Pkcs1);
            
            var base64EncryptedK1 = Convert.ToBase64String(encryptedK1);
            var base64EncryptedK2 = Convert.ToBase64String(encryptedK2);
            
            Console.WriteLine("Encrypted K1 : " + base64EncryptedK1);
            Console.WriteLine("Encrypted K2 : " + base64EncryptedK2);
            
            // RSA Decryption
            var decryptedK1 = rsa.GetCSP().Decrypt(encryptedK1, RSAEncryptionPadding.Pkcs1);
            var decryptedK2 = rsa.GetCSP().Decrypt(encryptedK2, RSAEncryptionPadding.Pkcs1);
            
            var decryptedDataK1 = Convert.ToBase64String(decryptedK1);
            var decryptedDataK2 = Convert.ToBase64String(decryptedK2);
            
            Console.WriteLine("Decrypted K1 : " + decryptedDataK1);
            Console.WriteLine("Decrypted K2 : " + decryptedDataK2);
            
            //1b for kb
            ECDiffieHellmanCng kb = new ECDiffieHellmanCng();
            
            kb.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            kb.HashAlgorithm = CngAlgorithm.Sha256;
            byte [] kbPublicKey = kb.PublicKey.ToByteArray();
            
            
            //1b for kc
            ECDiffieHellmanCng kc = new ECDiffieHellmanCng();
            kc.ExportParameters(true);
            kc.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            kc.HashAlgorithm = CngAlgorithm.Sha256;
            byte [] kcPublicKey = kb.PublicKey.ToByteArray();
            
            byte[] k3Key = kb.DeriveKeyMaterial(CngKey.Import(kcPublicKey, CngKeyBlobFormat.EccPublicBlob));
            byte[] k2Key = kc.DeriveKeyMaterial(CngKey.Import(kbPublicKey, CngKeyBlobFormat.EccPublicBlob));

            var k3KeyString = Convert.ToBase64String(k3Key);
            var k2KeyString = Convert.ToBase64String(k2Key);
            //2b kb and kc symmetric keys printed.
            Console.WriteLine("k3 key: " + k3KeyString);
            Console.WriteLine("k2 key: " + k2KeyString);
            //5a
            var hash = new HMACSHA256(k3Key);
            var hashBytes = Convert.ToBase64String(hash.ComputeHash(k3Key));
            
            Console.WriteLine("k3 with HMAC-SHA256: " + hashBytes);
            //5b
            var hmac = new HMACSHA256();
            var k2_HMAC_SHA256 = Convert.ToBase64String(hmac.ComputeHash(k2Key));
            
            Console.WriteLine("k2 with HMAC-SHA256: " + k2_HMAC_SHA256);
            
            
            // Part 3
            string plainText = "aaaaaaa";
            Console.WriteLine("Plain Text: " + plainText);

            byte[] plainTextArr = Encoding.ASCII.GetBytes(plainText);

            byte[] signature = rsa.GetCSP().SignData(plainTextArr, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Console.WriteLine("Digital Signature: " + Convert.ToBase64String(signature));

            bool verifySignature = rsa.GetCSP().VerifyData(plainTextArr, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Console.WriteLine("Is Digital Signature Verified?: " + verifySignature);
            
        }

        static string ComputeSha256Hash(string rawData)  
        {  
            // Create a SHA256   
            using (SHA256 sha256Hash = SHA256.Create())  
            {  
                // ComputeHash - returns byte array  
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));  
  
                // Convert byte array to a string   
                StringBuilder builder = new StringBuilder();  
                for (int i = 0; i < bytes.Length; i++)  
                {  
                    builder.Append(bytes[i].ToString("x2"));  
                }  
                return builder.ToString();  
            }  
        }  
       


     
    }
}
