using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Net.Mime;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Serialization;
using System.Drawing;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Policy;
using System.Threading;
using System.Drawing.Imaging;

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
            Console.WriteLine(" PART 1-2:");
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
            byte [] kcPublicKey = kc.PublicKey.ToByteArray();
            
            //2b kb and kc symmetric keys printed.
            byte[] k3Key = kb.DeriveKeyMaterial(CngKey.Import(kcPublicKey, CngKeyBlobFormat.EccPublicBlob));
            byte[] k3Key2 = kc.DeriveKeyMaterial(CngKey.Import(kbPublicKey, CngKeyBlobFormat.EccPublicBlob));

            var k3KeyString = Convert.ToBase64String(k3Key);
            var k3_2KeyString = Convert.ToBase64String(k3Key2);
            
            Console.WriteLine("k3 key: " + k3KeyString);
            Console.WriteLine("k3 key: " + k3_2KeyString);
            
            // Part 3 TO DO:
            Console.WriteLine(" \nPART 3:");
            string plainText = File.ReadAllText(@"..\..\Part3.txt");
            //Console.WriteLine("Plain Text: " + plainText);

            byte[] plainTextArr = Encoding.ASCII.GetBytes(plainText);

            using (HashAlgorithm algorithm = SHA256.Create())
            {
                var hashedPlainText = algorithm.ComputeHash(Encoding.UTF8.GetBytes(plainText));
                Console.WriteLine("SHA256 Hashed Text: " + Convert.ToBase64String(hashedPlainText));
            }
            
            byte[] signature = rsa.GetCSP().SignData(plainTextArr, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Console.WriteLine("Digital Signature: " + Convert.ToBase64String(signature));

            bool verifySignature = rsa.GetCSP().VerifyData(plainTextArr, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Console.WriteLine("Is Digital Signature Verified?: " + verifySignature);

            //4
            //Read Image File
            Console.WriteLine(" \nPART 4:");
            Image original_data = Image.FromFile(@"..\..\aang-Copy.jpg");
            byte[] original_data_arr = ImageToByteArray(original_data);
            String original_data_string = Convert.ToBase64String(original_data_arr);
            
            //i - AES 128 bit with CBC
            using (var random = new RNGCryptoServiceProvider())
            {
                // Key1 is 128 bit
                byte[] encrypted = EncryptStringToBytes_Aes(original_data_string, key1Generated);
                
                File.WriteAllBytes("EncryptedAES_128_CBC.txt", encrypted);
                
                // Decrypt the bytes to a string. 
                byte[] roundtrip = DecryptStringFromBytes_Aes(encrypted, key1Generated);
                
                File.WriteAllBytes("DecrptedAES_128_CBC.png", roundtrip);
                
                
                
                //Display the original data and the decrypted data.
                //Console.WriteLine("Original:   {0}", original_data_string);
                //Console.WriteLine("Encrypted (b64-encode): {0}", Convert.ToBase64String(encrypted));
                //Console.WriteLine("Round Trip: {0}", roundtrip);
            }
            
            //ii - AES 256 bit with CBC
            using (var random = new RNGCryptoServiceProvider())
            {

                // Encrypt the string to an array of bytes. 
                byte[] encrypted = EncryptStringToBytes_Aes(original_data_string, k3Key);
                
                File.WriteAllBytes("EncryptedAES_256_CBC.txt", encrypted);
                
                // Decrypt the bytes to a string. 
                byte[] roundtrip = DecryptStringFromBytes_Aes(encrypted, k3Key);

                File.WriteAllBytes("DecrptedAES_256_CBC.png", roundtrip);
                
                //Display the original data and the decrypted data.
                //Console.WriteLine("Original:   {0}", original_data_string);
                //Console.WriteLine("Encrypted (b64-encode): {0}", Convert.ToBase64String(encrypted));
                //Console.WriteLine("Round Trip: {0}", roundtrip);
            }

            //iii - AES 256 bit with CTR
            byte[] salt = new byte[16];
            ///encryption for iii.
            Stopwatch elapsedTimeenc = new Stopwatch();
            elapsedTimeenc.Start();
            using (Stream inputStream = File.OpenRead(@"..\..\aang-Copy.png"))
            using (Stream outputStream = File.Create("EncryptedAES_256_CTR.txt"))
            {
                AesCtrTransform(k3Key, salt, inputStream, outputStream);
            }
            elapsedTimeenc.Stop();
            String elapsedTimeString = (elapsedTimeenc.ElapsedMilliseconds).ToString();
            String elapRes =  String.Concat("AES 256 bit Encryption with CTR is completed in ", elapsedTimeString, " ms." );
            Console.WriteLine(elapRes);
            

            ///decryption for iii.
            Stopwatch elapsedTimedec = new Stopwatch();
            elapsedTimedec.Start();
            using (Stream inputStream = File.OpenRead("EncryptedAES_256_CTR.txt"))
            using (Stream outputStream = File.Create("DecryptedAES_256_CTR.png"))
            {
                AesCtrTransform(k3Key, salt, inputStream, outputStream);
            }
            elapsedTimedec.Stop();
            String elapsedTimeStringdec = (elapsedTimedec.ElapsedMilliseconds).ToString();
            //String elapResdec =  String.Concat("AES 256 bit decryption with CTR is completed in ", elapsedTimeStringdec, " ms." );
            //Console.WriteLine(elapResdec);

            Console.WriteLine(" \nPART 5:");
            //5a
            var hash = new HMACSHA256(k3Key);
            var hashBytes = Convert.ToBase64String(hash.ComputeHash(k3Key));
            
            Console.WriteLine("k3 with HMAC-SHA256: " + hashBytes);
            //5b
            var hmac = new HMACSHA256();
            var k2_HMAC_SHA256 = Convert.ToBase64String(hmac.ComputeHash(key2Generated));
            
            Console.WriteLine("k2 with HMAC-SHA256: " + k2_HMAC_SHA256);
            
        }


        public static void AesCtrTransform(byte[] key, byte[] salt, Stream inputStream, Stream outputStream)
        {
            SymmetricAlgorithm aes = new AesManaged { Mode = CipherMode.ECB, Padding = PaddingMode.None };

            int blockSize = aes.BlockSize / 8;

            if (salt.Length != blockSize)
            {
                throw new ArgumentException(
                    "Salt size must be same as block size " +
                    $"(actual: {salt.Length}, expected: {blockSize})");
            }

            byte[] counter = (byte[])salt.Clone();

            Queue<byte> xorMask = new Queue<byte>();

            var zeroIv = new byte[blockSize];
            ICryptoTransform counterEncryptor = aes.CreateEncryptor(key, zeroIv);

            int b;
            while ((b = inputStream.ReadByte()) != -1)
            {
                if (xorMask.Count == 0)
                {
                    var counterModeBlock = new byte[blockSize];

                    counterEncryptor.TransformBlock(
                        counter, 0, counter.Length, counterModeBlock, 0);

                    for (var i2 = counter.Length - 1; i2 >= 0; i2--)
                    {
                        if (++counter[i2] != 0)
                        {
                            break;
                        }
                    }

                    foreach (var b2 in counterModeBlock)
                    {
                        xorMask.Enqueue(b2);
                    }
                }

                var mask = xorMask.Dequeue();
                outputStream.WriteByte((byte)(((byte)b) ^ mask));
            }
        }
        
        
        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key)
        {
            byte[] encrypted;
            byte[] IV;
            //elapsed time for encryption 
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;

                aesAlg.GenerateIV();
                IV = aesAlg.IV;
                //Console.WriteLine(IV.Length);
                aesAlg.Mode = CipherMode.CBC;

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                
                
                
                // Create the streams used for encryption. 
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
                
            }

            var combinedIvCt = new byte[IV.Length + encrypted.Length];
            Array.Copy(IV, 0, combinedIvCt, 0, IV.Length);
            Array.Copy(encrypted, 0, combinedIvCt, IV.Length, encrypted.Length);
            
            stopwatch.Stop();
            Console.WriteLine("AES Encryption with CBC is completed in {0} ms", stopwatch.ElapsedMilliseconds);
            
            // Return the encrypted bytes from the memory stream. 
            return combinedIvCt;
        }
        
        static byte[] DecryptStringFromBytes_Aes(byte[] cipherTextCombined, byte[] Key)
        {
            
            // Declare the string used to hold 
            // the decrypted text. 
            byte[] plaintext = null;

            // Create an Aes object 
            // with the specified key and IV. 
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;

                byte[] IV = new byte[aesAlg.BlockSize/8];
                byte[] cipherText = new byte[cipherTextCombined.Length - IV.Length];
                
                Array.Copy(cipherTextCombined, IV, IV.Length);
                Array.Copy(cipherTextCombined, IV.Length, cipherText, 0, cipherText.Length);

                aesAlg.IV = IV;

                aesAlg.Mode = CipherMode.CBC;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption. 
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = Convert.FromBase64String(srDecrypt.ReadToEnd());
                        }
                    }
                }

            }

            return plaintext;

        }
        public static byte[] ImageToByteArray(Image img)
        {
            MemoryStream ms = new MemoryStream();
            img.Save(ms, System.Drawing.Imaging.ImageFormat.Gif);
            return ms.ToArray();
        }
    }
}
