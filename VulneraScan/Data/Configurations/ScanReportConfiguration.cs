using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using VulneraScan.Models;

namespace VulneraScan.Data.Configurations
{
    public class ScanReportConfiguration : IEntityTypeConfiguration<ScanReport>
    {
        public void Configure(EntityTypeBuilder<ScanReport> builder)
        {
            builder.HasKey(r => r.Id);

            builder.Property(r => r.Title)
                .IsRequired()
                .HasMaxLength(256);

            builder.Property(r => r.RiskLabel)
                .HasConversion<int>();

            builder.HasOne(r => r.ScanTarget)
                .WithOne(s => s.ScanReport)
                .HasForeignKey<ScanReport>(r => r.ScanTargetId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.HasOne(r => r.User)
                .WithMany(u => u.ScanReports)
                .HasForeignKey(r => r.UserId)
                .OnDelete(DeleteBehavior.Restrict);

            builder.HasIndex(r => r.ScanTargetId).IsUnique();
            builder.HasIndex(r => r.UserId);
            builder.HasIndex(r => r.GeneratedAt);
        }
    }
}
