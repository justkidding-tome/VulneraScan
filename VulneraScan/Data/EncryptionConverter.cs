using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using VulneraScan.Services;

namespace VulneraScan.Data
{
    /// <summary>
    /// EF Core value converter that automatically encrypts string properties on save
    /// and decrypts them on read. Integrates seamlessly with database operations.
    /// </summary>
    public class EncryptionConverter : ValueConverter<string, string>
    {
        /// <summary>
        /// Creates an encryption converter that encrypts data before storing in the database
        /// and decrypts data when reading from the database.
        /// </summary>
        /// <param name="encryptionService">The encryption service instance</param>
        public EncryptionConverter(IEncryptionService encryptionService)
            : base(
                // Convert to provider (encrypt before saving to database)
                v => string.IsNullOrEmpty(v) ? v : encryptionService.Encrypt(v),

                // Convert from provider (decrypt after reading from database)
                v => string.IsNullOrEmpty(v) ? v : encryptionService.Decrypt(v))
        {
        }
    }
}
