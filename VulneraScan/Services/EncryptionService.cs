using System.Security.Cryptography;
using System.Text;

namespace VulneraScan.Services
{
    /// <summary>
    /// Provides AES-256-GCM authenticated encryption for sensitive data.
    /// Uses environment-based key management for secure key storage.
    /// </summary>
    public interface IEncryptionService
    {
        /// <summary>
        /// Encrypts plaintext using AES-256-GCM.
        /// </summary>
        /// <param name="plaintext">The data to encrypt</param>
        /// <returns>Base64-encoded ciphertext with embedded nonce and tag</returns>
        string Encrypt(string plaintext);

        /// <summary>
        /// Decrypts ciphertext encrypted with AES-256-GCM.
        /// </summary>
        /// <param name="ciphertext">Base64-encoded ciphertext with embedded nonce and tag</param>
        /// <returns>Decrypted plaintext</returns>
        string Decrypt(string ciphertext);
    }

    /// <summary>
    /// Implementation of IEncryptionService using AES-256-GCM.
    /// Provides authenticated encryption to prevent tampering and unauthorized decryption.
    /// </summary>
    public class EncryptionService : IEncryptionService
    {
        private readonly byte[] _key;
        private readonly ILogger<EncryptionService> _logger;

        // GCM uses a 12-byte (96-bit) nonce for optimal performance and security
        private const int NonceSize = 12;

        // GCM authentication tag is 16 bytes (128 bits)
        private const int TagSize = 16;

        public EncryptionService(IConfiguration configuration, ILogger<EncryptionService> logger)
        {
            _logger = logger;

            // Load encryption key from environment variable
            var keyString = configuration["EncryptionKey:256"] 
                ?? Environment.GetEnvironmentVariable("ENCRYPTION_KEY_256");

            if (string.IsNullOrEmpty(keyString))
            {
                throw new InvalidOperationException(
                    "Encryption key not found. Set ENCRYPTION_KEY_256 environment variable or configure EncryptionKey:256 in appsettings.json. " +
                    "Generate a 32-byte (256-bit) key: new byte[32]; Convert.ToBase64String(key)");
            }

            try
            {
                _key = Convert.FromBase64String(keyString);

                // Validate key length for AES-256
                if (_key.Length != 32)
                {
                    throw new InvalidOperationException(
                        $"Encryption key must be exactly 32 bytes (256 bits) for AES-256. Current length: {_key.Length} bytes.");
                }
            }
            catch (FormatException ex)
            {
                throw new InvalidOperationException(
                    "Encryption key must be a valid Base64-encoded string.", ex);
            }
        }

        /// <summary>
        /// Encrypts plaintext using AES-256-GCM with a random nonce.
        /// Output format: [Nonce (12 bytes)][Ciphertext][Tag (16 bytes)] all Base64-encoded
        /// </summary>
        public string Encrypt(string plaintext)
        {
            if (string.IsNullOrEmpty(plaintext))
                return plaintext;

            try
            {
                using (var aes = new AesGcm(_key, TagSize))
                {
                    // Generate random nonce
                    byte[] nonce = new byte[NonceSize];
                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(nonce);
                    }

                    var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                    var ciphertext = new byte[plaintextBytes.Length];
                    var tag = new byte[TagSize];

                    // Encrypt with authenticated encryption
                    aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

                    // Combine nonce + ciphertext + tag and encode as Base64
                    var combined = new byte[nonce.Length + ciphertext.Length + tag.Length];
                    Buffer.BlockCopy(nonce, 0, combined, 0, nonce.Length);
                    Buffer.BlockCopy(ciphertext, 0, combined, nonce.Length, ciphertext.Length);
                    Buffer.BlockCopy(tag, 0, combined, nonce.Length + ciphertext.Length, tag.Length);

                    return Convert.ToBase64String(combined);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Encryption failed");
                throw new InvalidOperationException("Encryption operation failed.", ex);
            }
        }

        /// <summary>
        /// Decrypts ciphertext encrypted with AES-256-GCM.
        /// Extracts nonce, ciphertext, and tag from the combined Base64-encoded input.
        /// </summary>
        public string Decrypt(string ciphertext)
        {
            if (string.IsNullOrEmpty(ciphertext))
                return ciphertext;

            try
            {
                using (var aes = new AesGcm(_key, TagSize))
                {
                    // Decode the Base64 input
                    var combined = Convert.FromBase64String(ciphertext);

                    // Extract nonce, ciphertext, and tag
                    if (combined.Length < NonceSize + TagSize)
                    {
                        _logger.LogWarning("Decryption bypassed: input is too short to be a valid ciphertext. Returning original value.");
                        return ciphertext;
                    }

                    var nonce = new byte[NonceSize];
                    Buffer.BlockCopy(combined, 0, nonce, 0, NonceSize);

                    var encryptedData = new byte[combined.Length - NonceSize - TagSize];
                    Buffer.BlockCopy(combined, NonceSize, encryptedData, 0, encryptedData.Length);

                    var tag = new byte[TagSize];
                    Buffer.BlockCopy(combined, combined.Length - TagSize, tag, 0, TagSize);

                    // Decrypt with authenticated encryption (will throw if tag doesn't match)
                    var plaintextBytes = new byte[encryptedData.Length];
                    aes.Decrypt(nonce, encryptedData, tag, plaintextBytes);

                    return Encoding.UTF8.GetString(plaintextBytes);
                }
            }
            catch (FormatException)
            {
                _logger.LogWarning("Decryption bypassed: input is not a valid Base64-encoded ciphertext. Returning original value.");
                return ciphertext;
            }
            catch (CryptographicException)
            {
                _logger.LogWarning("Decryption failed: authentication tag verification failed. Returning original value.");
                return ciphertext;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Decryption failed");
                throw new InvalidOperationException("Decryption operation failed.", ex);
            }
        }
    }
}
