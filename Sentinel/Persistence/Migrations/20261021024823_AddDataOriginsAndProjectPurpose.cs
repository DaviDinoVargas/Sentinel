using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddDataOriginsAndProjectPurpose : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_audits_ProjectId",
                table: "audits");

            migrationBuilder.AddColumn<string>(
                name: "DataOrigin",
                table: "source_snapshots",
                type: "character varying(32)",
                maxLength: 32,
                nullable: false,
                defaultValue: "Unknown");

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "OriginDeclaredAtUtc",
                table: "source_snapshots",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "OriginDeclaredBy",
                table: "source_snapshots",
                type: "character varying(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Purpose",
                table: "projects",
                type: "character varying(32)",
                maxLength: 32,
                nullable: false,
                defaultValue: "SoftwareUnderTest");

            migrationBuilder.AddColumn<string>(
                name: "BaseFingerprint",
                table: "findings",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "DataOrigin",
                table: "findings",
                type: "character varying(32)",
                maxLength: 32,
                nullable: false,
                defaultValue: "Unknown");

            migrationBuilder.AddColumn<string>(
                name: "BaseFingerprint",
                table: "finding_observations",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "DataOrigin",
                table: "finding_observations",
                type: "character varying(32)",
                maxLength: 32,
                nullable: false,
                defaultValue: "Unknown");

            migrationBuilder.AddColumn<string>(
                name: "DataOrigin",
                table: "audits",
                type: "character varying(32)",
                maxLength: 32,
                nullable: false,
                defaultValue: "Unknown");

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "OriginDeclaredAtUtc",
                table: "audits",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "OriginDeclaredBy",
                table: "audits",
                type: "character varying(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "data_origin_events",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProjectId = table.Column<Guid>(type: "uuid", nullable: false),
                    AuditId = table.Column<Guid>(type: "uuid", nullable: true),
                    SnapshotId = table.Column<Guid>(type: "uuid", nullable: true),
                    FromOrigin = table.Column<string>(type: "text", nullable: false),
                    ToOrigin = table.Column<string>(type: "text", nullable: false),
                    Actor = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Reason = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: false),
                    AtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_data_origin_events", x => x.Id);
                    table.ForeignKey(
                        name: "FK_data_origin_events_audits_AuditId",
                        column: x => x.AuditId,
                        principalTable: "audits",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_data_origin_events_projects_ProjectId",
                        column: x => x.ProjectId,
                        principalTable: "projects",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_data_origin_events_source_snapshots_SnapshotId",
                        column: x => x.SnapshotId,
                        principalTable: "source_snapshots",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_audits_ProjectId_DataOrigin_CreatedAtUtc",
                table: "audits",
                columns: new[] { "ProjectId", "DataOrigin", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_data_origin_events_AuditId",
                table: "data_origin_events",
                column: "AuditId");

            migrationBuilder.CreateIndex(
                name: "IX_data_origin_events_ProjectId_AtUtc",
                table: "data_origin_events",
                columns: new[] { "ProjectId", "AtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_data_origin_events_SnapshotId",
                table: "data_origin_events",
                column: "SnapshotId");
            migrationBuilder.Sql("""
                CREATE FUNCTION sentinel_data_origin_event_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'Origin events are append-only'; END $$;
                CREATE TRIGGER data_origin_events_append_only BEFORE UPDATE OR DELETE ON data_origin_events
                FOR EACH ROW EXECUTE FUNCTION sentinel_data_origin_event_immutable();
                ALTER TABLE data_origin_events ADD CONSTRAINT data_origin_event_target CHECK (("AuditId" IS NULL) <> ("SnapshotId" IS NULL));
                ALTER TABLE audits ADD CONSTRAINT audits_origin_values CHECK ("DataOrigin" IN ('Unknown','SoftwareUnderTest','SyntheticCorpus'));
                ALTER TABLE source_snapshots ADD CONSTRAINT snapshots_origin_values CHECK ("DataOrigin" IN ('Unknown','SoftwareUnderTest','SyntheticCorpus'));
                ALTER TABLE findings ADD CONSTRAINT findings_origin_values CHECK ("DataOrigin" IN ('Unknown','SoftwareUnderTest','SyntheticCorpus'));
                ALTER TABLE finding_observations ADD CONSTRAINT observations_origin_values CHECK ("DataOrigin" IN ('Unknown','SoftwareUnderTest','SyntheticCorpus'));
                ALTER TABLE projects ADD CONSTRAINT projects_purpose_values CHECK ("Purpose" IN ('SoftwareUnderTest','SentinelValidation'));
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DROP FUNCTION IF EXISTS sentinel_data_origin_event_immutable() CASCADE; ALTER TABLE audits DROP CONSTRAINT IF EXISTS audits_origin_values; ALTER TABLE source_snapshots DROP CONSTRAINT IF EXISTS snapshots_origin_values; ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_origin_values; ALTER TABLE finding_observations DROP CONSTRAINT IF EXISTS observations_origin_values; ALTER TABLE projects DROP CONSTRAINT IF EXISTS projects_purpose_values;");
            migrationBuilder.DropTable(
                name: "data_origin_events");

            migrationBuilder.DropIndex(
                name: "IX_audits_ProjectId_DataOrigin_CreatedAtUtc",
                table: "audits");

            migrationBuilder.DropColumn(
                name: "DataOrigin",
                table: "source_snapshots");

            migrationBuilder.DropColumn(
                name: "OriginDeclaredAtUtc",
                table: "source_snapshots");

            migrationBuilder.DropColumn(
                name: "OriginDeclaredBy",
                table: "source_snapshots");

            migrationBuilder.DropColumn(
                name: "Purpose",
                table: "projects");

            migrationBuilder.DropColumn(
                name: "BaseFingerprint",
                table: "findings");

            migrationBuilder.DropColumn(
                name: "DataOrigin",
                table: "findings");

            migrationBuilder.DropColumn(
                name: "BaseFingerprint",
                table: "finding_observations");

            migrationBuilder.DropColumn(
                name: "DataOrigin",
                table: "finding_observations");

            migrationBuilder.DropColumn(
                name: "DataOrigin",
                table: "audits");

            migrationBuilder.DropColumn(
                name: "OriginDeclaredAtUtc",
                table: "audits");

            migrationBuilder.DropColumn(
                name: "OriginDeclaredBy",
                table: "audits");

            migrationBuilder.CreateIndex(
                name: "IX_audits_ProjectId",
                table: "audits",
                column: "ProjectId");
        }
    }
}
