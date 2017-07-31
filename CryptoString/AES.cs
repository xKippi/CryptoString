using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

public class AES
{
    private static byte[] _defaulSalt = { 0xDE, 0xFA, 0xCE, 112, 117, 098, 108, 105, 099, 032, 099, 108, 097, 115, 115, 032, 067, 114, 121, 112, 116, 111, 013, 010, 123, 013, 010, 013, 010, 032, 032, 032, 032, 047, 047, 087, 104, 105, 108, 101, 032, 097, 110, 032, 097, 112, 112, 032, 115, 112, 101, 099, 105, 102, 105, 099, 032, 115, 097, 108, 116, 032, 105, 115, 032, 110, 111, 116, 032, 116, 104, 101, 032, 098, 101, 115, 116, 032, 112, 114, 097, 099, 116, 105, 099, 101, 032, 102, 111, 114, 013, 010, 032, 032, 032, 032, 047, 047, 112, 097, 115, 115, 119, 111, 114, 100, 032, 098, 097, 115, 101, 100, 032, 101, 110, 099, 114, 121, 112, 116, 105, 111, 110, 044, 032, 105, 116, 039, 115, 032, 112, 114, 111, 098, 097, 098, 108, 121, 032, 115, 097, 102, 101, 032, 101, 110, 111, 117, 103, 104, 032, 097, 115, 032, 108, 111, 110, 103, 032, 097, 115, 013, 010, 032, 032, 032, 032, 047, 047, 105, 116, 032, 105, 115, 032, 116, 114, 117, 108, 121, 032, 117, 110, 099, 111, 109, 109, 111, 110, 046, 032, 065, 108, 115, 111, 032, 116, 111, 111, 032, 109, 117, 099, 104, 032, 119, 111, 114, 107, 032, 116, 111, 032, 097, 108, 116, 101, 114, 032, 116, 104, 105, 115, 032, 097, 110, 115, 119, 101, 114, 032, 111, 116, 104, 101, 114, 119, 105, 115, 101, 046, 013, 010, 032, 032, 032, 032, 112, 114, 105, 118, 097, 116, 101, 032, 115, 116, 097, 116, 105, 099, 032, 098, 121, 116, 101, 091, 093, 032, 095, 115, 097, 108, 116, 032, 061, 032, 095, 095, 084, 111, 095, 068, 111, 095, 095, 040, 034, 065, 100, 100, 032, 097, 032, 097, 112, 112, 032, 115, 112, 101, 099, 105 };
    private const int _defaultIterations = 100000;

#region EncryptString
    /// <summary>
    /// Encrypt the given string using AES.  The string can be decrypted using 
    /// DecryptStringAES().  The sharedSecret parameters must match.
    /// </summary>
    /// <param name="plainText">The text to encrypt.</param>
    /// <param name="sharedSecret">A password used to generate a key for encryption.</param>
    public static string EncryptString(string plainText, string sharedSecret)
    {
        return EncryptString(plainText, sharedSecret, ref _defaulSalt, _defaultIterations);
    }

    /// <summary>
    /// Encrypt the given string using AES.  The string can be decrypted using 
    /// DecryptStringAES().  The sharedSecret parameters must match.
    /// </summary>
    /// <param name="plainText">The text to encrypt.</param>
    /// <param name="sharedSecret">A password used to generate a key for encryption.</param>
    /// <param name="iterations">How many iterations should be used to generate the key.</param>
    public static string EncryptString(string plainText, string sharedSecret, int iterations)
    {
        return EncryptString(plainText, sharedSecret, ref _defaulSalt, iterations);
    }

    /// <summary>
    /// Encrypt the given string using AES.  The string can be decrypted using 
    /// DecryptStringAES().  The sharedSecret parameters must match.
    /// </summary>
    /// <param name="plainText">The text to encrypt.</param>
    /// <param name="sharedSecret">A password used to generate a key for encryption.</param>
    /// <param name="salt">The salt for the key generation.</param>
    public static string EncryptString(string plainText, string sharedSecret, ref byte[] salt)
    {
        return EncryptString(plainText, sharedSecret, ref salt, _defaultIterations);
    }

    /// <summary>
    /// Encrypt the given string using AES.  The string can be decrypted using 
    /// DecryptStringAES().  The sharedSecret parameters must match.
    /// </summary>
    /// <param name="plainText">The text to encrypt.</param>
    /// <param name="sharedSecret">A password used to generate a key for encryption.</param>
    /// <param name="salt">The salt for the key generation.</param>
    /// <param name="iterations">How many iterations should be used to generate the key.</param>
    public static string EncryptString(string plainText, string sharedSecret, ref byte[] salt, int iterations)
    {
        if (string.IsNullOrEmpty(plainText))
            throw new ArgumentNullException("plainText");
        if (string.IsNullOrEmpty(sharedSecret))
            throw new ArgumentNullException("sharedSecret");

        string outStr = null;                       // Encrypted string to return
        RijndaelManaged aesAlg = null;              // RijndaelManaged object used to encrypt the data.

        try
        {

            // generate the key from the shared secret and the salt
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, salt, iterations);

            // Create a RijndaelManaged object
            aesAlg = new RijndaelManaged();
            aesAlg.KeySize = 256;
            aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);

            // Create a encryptor to perform the stream transform.
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for encryption.
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                // prepend the IV
                msEncrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));
                msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }
                }
                outStr = Convert.ToBase64String(msEncrypt.ToArray());
            }
        }
        finally
        {
            // Clear the RijndaelManaged object.
            if (aesAlg != null)
                aesAlg.Clear();
        }

        // Return the encrypted bytes from the memory stream.
        return outStr;
    }
    #endregion

#region DecryptString
    /// <summary>
    /// Decrypt the given string.  Assumes the string was encrypted using 
    /// EncryptStringAES(), using an identical sharedSecret.
    /// </summary>
    /// <param name="cipherText">The text to decrypt.</param>
    /// <param name="sharedSecret">A password used to generate a key for decryption.</param>
    public static string DecryptString(string cipherText, string sharedSecret)
    {
        return DecryptString(cipherText, sharedSecret, ref _defaulSalt, _defaultIterations);
    }

    /// <summary>
    /// Decrypt the given string.  Assumes the string was encrypted using 
    /// EncryptStringAES(), using an identical sharedSecret.
    /// </summary>
    /// <param name="cipherText">The text to decrypt.</param>
    /// <param name="sharedSecret">A password used to generate a key for decryption.</param>
    /// <param name="iterations">How many iterations should be used to generate the key.</param>
    public static string DecryptString(string cipherText, string sharedSecret, int iterations)
    {
        return DecryptString(cipherText, sharedSecret, ref _defaulSalt, iterations);
    }

    /// <summary>
    /// Decrypt the given string.  Assumes the string was encrypted using 
    /// EncryptStringAES(), using an identical sharedSecret.
    /// </summary>
    /// <param name="cipherText">The text to decrypt.</param>
    /// <param name="sharedSecret">A password used to generate a key for decryption.</param>
    /// <param name="salt">The salt for the key generation.</param>
    public static string DecryptString(string cipherText, string sharedSecret, ref byte[] salt)
    {
        return DecryptString(cipherText, sharedSecret, ref salt, _defaultIterations);
    }

    /// <summary>
    /// Decrypt the given string.  Assumes the string was encrypted using 
    /// EncryptStringAES(), using an identical sharedSecret.
    /// </summary>
    /// <param name="cipherText">The text to decrypt.</param>
    /// <param name="sharedSecret">A password used to generate a key for decryption.</param>    
    /// <param name="salt">The salt for the key generation.</param>
    /// <param name="iterations">How many iterations should be used to generate the key.</param>
    public static string DecryptString(string cipherText, string sharedSecret, ref byte[] salt, int iterations)
    {
        if (string.IsNullOrEmpty(cipherText))
            throw new ArgumentNullException("cipherText");
        if (string.IsNullOrEmpty(sharedSecret))
            throw new ArgumentNullException("sharedSecret");

        // Declare the RijndaelManaged object
        // used to decrypt the data.
        RijndaelManaged aesAlg = null;

        // Declare the string used to hold
        // the decrypted text.
        string plaintext = null;

        try
        {
            // generate the key from the shared secret and the salt
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, salt, iterations);

            // Create the streams used for decryption.                
            byte[] bytes = Convert.FromBase64String(cipherText);
            using (MemoryStream msDecrypt = new MemoryStream(bytes))
            {
                // Create a RijndaelManaged object
                // with the specified key and IV.
                aesAlg = new RijndaelManaged();
                aesAlg.KeySize = 256;
                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                // Get the initialization vector from the encrypted stream
                aesAlg.IV = ReadByteArray(msDecrypt);
                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))

                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        plaintext = srDecrypt.ReadToEnd();
                }
            }
        }
        finally
        {
            // Clear the RijndaelManaged object.
            if (aesAlg != null)
                aesAlg.Clear();
        }

        return plaintext;
    }
    #endregion

#region RandomSalts
    public static byte[] RandomANSISalt(int length)
    {
        return RandomANSISalt(length, new char[0]);
    }
    public static byte[] RandomANSISalt(int length, params char[] forbiddenChars)
    {
        byte[] forbiddenBytes = System.Text.Encoding.GetEncoding(1252).GetBytes(forbiddenChars);

        using (RNGCryptoServiceProvider random = new RNGCryptoServiceProvider())
        {
            byte[] result = new byte[length];
            random.GetBytes(result);
            for (int i = 0; i < length; i++)
                while (result[i] <= 32 || result[i] == 127 || result[i] == 255 || forbiddenBytes.Contains(result[i]))
                {
                    byte[] oneByte = new byte[1];
                    random.GetBytes(oneByte);
                    result[i] = oneByte[0];
                }

            return result;
        }
    }
    public static byte[] RandomASCIISalt(int length)
    {
        return RandomASCIISalt(length, new char[0]);
    }
    public static byte[] RandomASCIISalt(int length, params char[] forbiddenChars)
    {
        byte[] forbiddenBytes = System.Text.Encoding.ASCII.GetBytes(forbiddenChars);
        for (int i = 0; i < forbiddenBytes.Length; i++)
            if (forbiddenBytes[i] > 127)
                throw new ArgumentException("forbiddenChars may only contain ASCII chars", "forbiddenChars");

        using (RNGCryptoServiceProvider random = new RNGCryptoServiceProvider())
        {
            byte[] result = new byte[length];
            random.GetBytes(result);
            for (int i = 0; i < length; i++)
                while (result[i] <= 32 || result[i] >= 127 || forbiddenBytes.Contains(result[i]))
                {
                    byte[] oneByte = new byte[1];
                    random.GetBytes(oneByte);
                    result[i] = oneByte[0];
                }

            return result;
        }
    }
    public static byte[] RandomSalt(int length)
    {
        using (RNGCryptoServiceProvider random = new RNGCryptoServiceProvider())
        {
            byte[] result = new byte[length];
            random.GetBytes(result);

            return result;
        }
    }
#endregion

    private static byte[] ReadByteArray(Stream s)
    {
        byte[] rawLength = new byte[sizeof(int)];
        if (s.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
        {
            throw new SystemException("Stream did not contain properly formatted byte array");
        }

        byte[] buffer = new byte[BitConverter.ToInt32(rawLength, 0)];
        if (s.Read(buffer, 0, buffer.Length) != buffer.Length)
        {
            throw new SystemException("Did not read byte array properly");
        }

        return buffer;
    }
}