using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_DotNet6.Security
{
    public enum EncryptionType {Enc128, Enc192, Enc256};
    public class Encryption
    {
        private static int SaltValueSize = 32;
        // The higher the number the better but also the slow it will be
        private static int InterationCount = 1000;


        
        /// <summary>
        /// Uses a password to create a private key and then encrypts the passed in data
        /// </summary>
        /// <param name="TextToEncrypt">The string to encrypt</param>
        /// <param name="passPhrase">The password to use to encrypt the data</param>
        /// <param name="encryptionStrength">The private key size</param>
        /// <returns>The Encrypted data or String.Empty if anything went wrong</returns>
        public static string Encrypt(string TextToEncrypt, string passPhrase, EncryptionType encryptionStrength)
        {
            try
            { 
                byte[] SaltValue;

                // create some random numbers. This will be used allong with the password string passed in
                // to create a private key
                SaltValue = Encryption.GenerateSaltValue(Encryption.SaltValueSize);

                // Turns the plane text password into a private encryption key
                Rfc2898DeriveBytes PrivateKey = new Rfc2898DeriveBytes(passPhrase, SaltValue, Encryption.InterationCount);


                // Encrypt the data.
                Aes encAlg = Aes.Create();
                // 16 = 128 bit encryption. 24 = 192 bit encryption. 32 = 256 bit encryption.
                // default is 16 to pass in (128 bit encryption). Might need to change key size if want to use any other size of encryption
                //encAlg.Key = PrivateKey.GetBytes(16);
                switch (encryptionStrength)
                {
                    case EncryptionType.Enc128:
                        encAlg.KeySize = 128;
                        encAlg.Key = PrivateKey.GetBytes(16);
                    
                        break;

                    case EncryptionType.Enc192:
                        encAlg.KeySize = 192;
                        encAlg.Key = PrivateKey.GetBytes(24);
                    
                        break;

                    case EncryptionType.Enc256:
                        encAlg.KeySize = 256;
                        encAlg.Key = PrivateKey.GetBytes(32);
                    
                        break;

                }
                MemoryStream encryptionStream = new MemoryStream();
                CryptoStream encrypt = new CryptoStream(encryptionStream,encAlg.CreateEncryptor(), CryptoStreamMode.Write);
                // convert the unencrypted text to a byte array
                byte[] utfD1 = new System.Text.UTF8Encoding(false).GetBytes(TextToEncrypt);

                // write the unencrypted data into the Crypto Stream (this is where it will get encrypted)
                encrypt.Write(utfD1, 0, utfD1.Length);
                encrypt.FlushFinalBlock();
                encrypt.Close();
                // get back the encrypted data as a byte array
                byte[] EncryptedDataInByteArray = encryptionStream.ToArray();
                PrivateKey.Reset();

            
                // Convert the byte array to a base 64 value and add the salt and iv values into the data.
                //
                // add the randomly generated salt value & IV to the begining of the ecrypted data
                // then convert the hole thing to base64.
                // The salt value & IV are needed when we want to decrypt the data, so we need to store them somewhere.
                // Good place might be the database, but we are going to put it in with the encrypted data.
                // While not a good idea the user still can't decrypt the data without the password
                // and they would need to know we stored the salt value at the begining of the encrypted data.
                return Convert.ToBase64String(SaltValue.Concat(encAlg.IV).Concat(EncryptedDataInByteArray).ToArray());
            }
            catch (Exception ex)
            {
                return String.Empty;
            }
        }

        /// <summary>
        ///  Using a password phrase decrypt the passed in data back to plain text
        /// </summary>
        /// <param name="TextToDecrypt">The encrypted data</param>
        /// <param name="passPhrase">The password to use to decrypt the data</param>
        /// <param name="encryptionStrength">The private key size</param>
        /// <returns>The Dycrypted data or String.Empty if anything went wrong</returns>
        public static string Decrypt(string TextToDecrypt, string passPhrase, EncryptionType encryptionStrength)
        {
            try
            {
                // convert the passed in data to a byte array.
                // The passed in data has the salt value & IV stored at the begining of it and then the encrypted data after it.
                // we will need to seperate these out.
                // The Iv size was done when data was being encrypted. It is the size of the blocks when they are encrypted
                // It is normaly 16 is basicaly Aes.BlockSize / 8
                int IVSize = 16;
                byte[] SaltIVAndEncryptedData = Convert.FromBase64String(TextToDecrypt);
                // get the salt value
                byte[] SaltValue = SaltIVAndEncryptedData.Take(Encryption.SaltValueSize).ToArray();
                // get the IV Value (its size is Aes.BlockSize / 8) Default value is 16 (its the size the blocks have been encrypted in)
                byte[] IVValue = SaltIVAndEncryptedData.Skip(Encryption.SaltValueSize).Take(IVSize).ToArray();
                // get the encrypted data
                byte[] EncryptedData = SaltIVAndEncryptedData.Skip(SaltValueSize + IVSize).Take(SaltIVAndEncryptedData.Length - (SaltValueSize + IVSize)).ToArray();

                // turn the plain text password into a private key
                Rfc2898DeriveBytes PrivateKey = new Rfc2898DeriveBytes(passPhrase, SaltValue);

                Aes decAlg = Aes.Create();
                //decAlg.Key = PrivateKey.GetBytes(16);
                // the the key size we will be  using
                switch (encryptionStrength)
                {
                    case EncryptionType.Enc128:
                        decAlg.KeySize = 128;
                        decAlg.Key = PrivateKey.GetBytes(16);

                        break;

                    case EncryptionType.Enc192:
                        decAlg.KeySize = 192;
                        decAlg.Key = PrivateKey.GetBytes(24);

                        break;

                    case EncryptionType.Enc256:
                        decAlg.KeySize = 256;
                        decAlg.Key = PrivateKey.GetBytes(32);

                        break;

                }
                decAlg.IV = IVValue;

                MemoryStream decryptionStreamBacking = new MemoryStream();
                CryptoStream decrypt = new CryptoStream(decryptionStreamBacking, decAlg.CreateDecryptor(), CryptoStreamMode.Write);
                decrypt.Write(EncryptedData, 0, EncryptedData.Length);
                decrypt.Flush();
                decrypt.Close();
                PrivateKey.Reset();

                // Get the decrypted data back as a string (how it was before it was encrypted)
                string DecreptedData = new UTF8Encoding(false).GetString(decryptionStreamBacking.ToArray());

                return DecreptedData;
            }
            catch(Exception e)
            {
                return string.Empty;
            }
        }


        /// <summary>
        /// Creates random numbers and returns them in a byte array
        /// </summary>
        /// <param name="size">The numbe of random numbers to create</param>
        /// <returns>Random numbers in a byte array</returns>
        public static byte[] GenerateSaltValue(int size)
        {
            byte[] salt = new byte[size];
            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with a random value.
                rngCsp.GetBytes(salt);
            }

            return salt;
        }
    }
}
