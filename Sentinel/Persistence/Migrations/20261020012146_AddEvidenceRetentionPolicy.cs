using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddEvidenceRetentionPolicy : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "EvidencePolicyUpdatedAtUtc",
                table: "projects",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "EvidencePolicyUpdatedBy",
                table: "projects",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "EvidenceRetentionDays",
                table: "projects",
                type: "integer",
                nullable: false,
                defaultValue: 30);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EvidencePolicyUpdatedAtUtc",
                table: "projects");

            migrationBuilder.DropColumn(
                name: "EvidencePolicyUpdatedBy",
                table: "projects");

            migrationBuilder.DropColumn(
                name: "EvidenceRetentionDays",
                table: "projects");
        }
    }
}
