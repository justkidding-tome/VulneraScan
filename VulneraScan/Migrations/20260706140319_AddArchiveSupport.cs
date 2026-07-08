using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VulneraScan.Migrations
{
    /// <inheritdoc />
    public partial class AddArchiveSupport : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsArchived",
                table: "ScanTargets",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "IsArchived",
                table: "ScanReports",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "IsArchived",
                table: "AspNetUsers",
                type: "bit",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsArchived",
                table: "ScanTargets");

            migrationBuilder.DropColumn(
                name: "IsArchived",
                table: "ScanReports");

            migrationBuilder.DropColumn(
                name: "IsArchived",
                table: "AspNetUsers");
        }
    }
}
