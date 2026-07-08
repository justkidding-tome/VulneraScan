using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using VulneraScan.Models;

namespace VulneraScan.Data.Configurations
{
    public class PortResultConfiguration : IEntityTypeConfiguration<PortResult>
    {
        public void Configure(EntityTypeBuilder<PortResult> builder)
        {
            builder.HasKey(p => p.Id);

            builder.Property(p => p.Status)
                .HasConversion<int>();

            builder.Property(p => p.RiskLevel)
                .HasConversion<int>();

            builder.HasOne(p => p.ScanTarget)
                .WithMany(s => s.PortResults)
                .HasForeignKey(p => p.ScanTargetId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.HasIndex(p => p.ScanTargetId);
        }
    }
}
