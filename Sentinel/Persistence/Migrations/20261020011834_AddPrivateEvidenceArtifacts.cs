using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPrivateEvidenceArtifacts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ArtifactMetadataJson",
                table: "audit_evidence",
                type: "jsonb",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ArtifactReference",
                table: "audit_evidence",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "PurgedAtUtc",
                table: "audit_evidence",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "RetainUntilUtc",
                table: "audit_evidence",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_audit_evidence_RetainUntilUtc",
                table: "audit_evidence",
                column: "RetainUntilUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_audit_evidence_RetainUntilUtc",
                table: "audit_evidence");

            migrationBuilder.DropColumn(
                name: "ArtifactMetadataJson",
                table: "audit_evidence");

            migrationBuilder.DropColumn(
                name: "ArtifactReference",
                table: "audit_evidence");

            migrationBuilder.DropColumn(
                name: "PurgedAtUtc",
                table: "audit_evidence");

            migrationBuilder.DropColumn(
                name: "RetainUntilUtc",
                table: "audit_evidence");
        }
    }
}
