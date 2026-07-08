using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using VulneraScan.Models;

namespace VulneraScan.Data.Configurations
{
    public class DiscoveredServiceConfiguration : IEntityTypeConfiguration<DiscoveredService>
    {
        public void Configure(EntityTypeBuilder<DiscoveredService> builder)
        {
            builder.HasKey(d => d.Id);

            builder.Property(d => d.ServiceName)
                .IsRequired()
                .HasMaxLength(100);

            builder.Property(d => d.RiskLevel)
                .HasConversion<int>();

            builder.HasOne(d => d.ScanTarget)
                .WithMany(s => s.DiscoveredServices)
                .HasForeignKey(d => d.ScanTargetId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.HasIndex(d => d.ScanTargetId);
        }
    }
}
