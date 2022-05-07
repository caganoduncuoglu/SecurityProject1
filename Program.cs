using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Xml.Serialization;

namespace SecurityProject1
{
    public class RSAEncryption
    {
        private static RSACryptoServiceProvider csp = new RSACryptoServiceProvider(1024);
        private RSAParameters _privateKey;
        private RSAParameters _publicKey;
        
        public RSAEncryption()
        {
            _privateKey = csp.ExportParameters(true);
            _publicKey = csp.ExportParameters(false);
        }

        public RSACryptoServiceProvider GetCSP()
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
            var encryptedK1 = rsa.GetCSP().Encrypt(key1Generated, true);
            var encryptedK2 = rsa.GetCSP().Encrypt(key2Generated, true);
            
            var base64EncryptedK1 = Convert.ToBase64String(encryptedK1);
            var base64EncryptedK2 = Convert.ToBase64String(encryptedK2);
            
            Console.WriteLine("Encrypted K1 : " + base64EncryptedK1);
            Console.WriteLine("Encrypted K2 : " + base64EncryptedK2);
            
            // RSA Decryption
            var decryptedK1 = rsa.GetCSP().Decrypt(encryptedK1, true);
            var decryptedK2 = rsa.GetCSP().Decrypt(encryptedK2, true);
            
            var decryptedDataK1 = Convert.ToBase64String(decryptedK1);
            var decryptedDataK2 = Convert.ToBase64String(decryptedK2);
            
            Console.WriteLine("Decrypted K1 : " + decryptedDataK1);
            Console.WriteLine("Decrypted K2 : " + decryptedDataK2);


        }
    }
}
