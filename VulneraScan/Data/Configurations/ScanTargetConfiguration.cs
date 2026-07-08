using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using VulneraScan.Models;

namespace VulneraScan.Data.Configurations
{
    public class ScanTargetConfiguration : IEntityTypeConfiguration<ScanTarget>
    {
        public void Configure(EntityTypeBuilder<ScanTarget> builder)
        {
            builder.HasKey(s => s.Id);

            builder.Property(s => s.TargetUrl)
                .IsRequired()
                .HasMaxLength(2048);

            builder.Property(s => s.IpAddress)
                .HasMaxLength(45);

            builder.Property(s => s.Domain)
                .HasMaxLength(255);

            builder.Property(s => s.ScanStatus)
                .HasConversion<int>();

            builder.HasOne(s => s.User)
                .WithMany(u => u.ScanTargets)
                .HasForeignKey(s => s.UserId)
                .OnDelete(DeleteBehavior.Restrict);

            builder.HasIndex(s => s.UserId);
            builder.HasIndex(s => s.CreatedAt);
        }
    }
}
