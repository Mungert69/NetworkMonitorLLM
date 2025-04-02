using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.IO;


namespace NetworkMonitor.Utils
{
    public static class AesOperation
    {
        public static byte[] GenerateKey(byte[] salt, string passphrase)
        {
            return KeyDerivation.Pbkdf2(
                password: passphrase,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: 32); // 256-bit key
        }
        public static string DecryptString(string passphrase, string base64EncryptedData)
        {
            // Unencode from base64
            byte[] encryptedData = Convert.FromBase64String(base64EncryptedData);
            using (var aes = Aes.Create())
            {
                int ivSize = aes.BlockSize / 8;
                byte[] iv = new byte[ivSize];
                byte[] salt = new byte[16];
                byte[] encrypted = new byte[encryptedData.Length - ivSize - salt.Length];
                Array.Copy(encryptedData, iv, ivSize);
                Array.Copy(encryptedData, ivSize, encrypted, 0, encrypted.Length);
                Array.Copy(encryptedData, ivSize + encrypted.Length, salt, 0, salt.Length);
                aes.Key = GenerateKey(salt, passphrase);
                aes.IV = iv;
                var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                string decrypted;
                using (var memoryStream = new System.IO.MemoryStream(encrypted))
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        byte[] buffer = new byte[encrypted.Length];
                        int bytesRead = cryptoStream.Read(buffer, 0, buffer.Length);
                        // Remove padding
                        int unpaddedLength = bytesRead;
                        for (int i = bytesRead - 1; i >= bytesRead - aes.BlockSize / 8; i--)
                        {
                            if (buffer[i] == 0)
                            {
                                unpaddedLength--;
                            }
                            else
                            {
                                break;
                            }
                        }
                        decrypted = Encoding.UTF8.GetString(buffer, 0, unpaddedLength);
                    }
                }
                return decrypted;
            }
        }

        public static string EncryptString(string passphrase, string data)
        {
            var salt = SaltGeneration.GenerateSalt(16);
            var key = GenerateKey(salt, passphrase);
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.GenerateIV();
                var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                byte[] encrypted;
                using (var memoryStream = new System.IO.MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                        // Add padding to ensure the data is a multiple of the block size
                        int blockSizeInBytes = aes.BlockSize / 8;
                        int paddedLength = ((dataBytes.Length + blockSizeInBytes - 1) / blockSizeInBytes) * blockSizeInBytes;
                        byte[] paddedData = new byte[paddedLength];
                        Array.Copy(dataBytes, paddedData, dataBytes.Length);
                        cryptoStream.Write(paddedData, 0, paddedData.Length);
                    }
                    encrypted = memoryStream.ToArray();
                }
                // Append IV to encrypted data for use in decryption later
                byte[] encryptedData = new byte[aes.IV.Length + encrypted.Length + salt.Length];
                aes.IV.CopyTo(encryptedData, 0);
                encrypted.CopyTo(encryptedData, aes.IV.Length);
                salt.CopyTo(encryptedData, aes.IV.Length + encrypted.Length);
                // encode to base64 for storage
                string base64EncryptedData = Convert.ToBase64String(encryptedData);
                return base64EncryptedData;
            }
        }

        public static void GenerateKeyAndIV(string passphrase, out byte[] key, out byte[] iv)
        {
            byte[] salt = Encoding.UTF8.GetBytes("YourUniqueSaltHere"); // Consider making this dynamic or configurable

            using (var pbkdf2 = new Rfc2898DeriveBytes(passphrase, salt, 10000, HashAlgorithmName.SHA256))
            {
                key = pbkdf2.GetBytes(16); // 128-bit key
                iv = pbkdf2.GetBytes(16);  // 128-bit IV
            }
        }

        public static string SimpleEncryptString(string passphrase, string data)
        {
            GenerateKeyAndIV(passphrase, out byte[] key, out byte[] iv);

            using (MemoryStream msEncrypt = new MemoryStream())
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Mode = CipherMode.CFB;
                aesAlg.Padding = PaddingMode.None;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write, leaveOpen: true))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(data);
                    }
                }

                byte[] encrypted = msEncrypt.ToArray();
                string base64String = Convert.ToBase64String(encrypted);
                string urlSafeBase64String = base64String.Replace("+", "-").Replace("/", "_");
                return urlSafeBase64String;

            }
        }

        public static string SimpleDecryptString(string passphrase, string urlSafeBase64EncryptedData)
        {
            GenerateKeyAndIV(passphrase, out byte[] key, out byte[] iv);

            string standardBase64EncryptedData = urlSafeBase64EncryptedData.Replace("-", "+").Replace("_", "/");
            byte[] cipherText = Convert.FromBase64String(standardBase64EncryptedData);

            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Mode = CipherMode.CFB;
                aesAlg.Padding = PaddingMode.None;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read, leaveOpen: true))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }

    }

    // Adjusted to use a passphrase directly and generate both key and IV
}
