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
        
        public string GetPublicKey()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw,_publicKey);
            return sw.ToString();
        }
        
        public string GetPrivateKey()
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
        }
    }
}
