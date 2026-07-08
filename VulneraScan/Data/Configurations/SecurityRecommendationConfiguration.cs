using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using VulneraScan.Models;

namespace VulneraScan.Data.Configurations
{
    public class SecurityRecommendationConfiguration : IEntityTypeConfiguration<SecurityRecommendation>
    {
        public void Configure(EntityTypeBuilder<SecurityRecommendation> builder)
        {
            builder.HasKey(r => r.Id);

            builder.Property(r => r.Title)
                .IsRequired()
                .HasMaxLength(256);

            builder.Property(r => r.Priority)
                .HasConversion<int>();

            builder.HasOne(r => r.Vulnerability)
                .WithOne(v => v.Recommendation)
                .HasForeignKey<SecurityRecommendation>(r => r.VulnerabilityId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.HasIndex(r => r.VulnerabilityId).IsUnique();
        }
    }
}
