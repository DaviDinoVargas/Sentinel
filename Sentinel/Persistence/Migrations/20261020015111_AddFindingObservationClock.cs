using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddFindingObservationClock : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "TimeSource",
                table: "finding_observations",
                type: "text",
                nullable: false,
                defaultValue: "AuditCreated");
            migrationBuilder.Sql("""
                UPDATE finding_observations o SET "TimeSource"='Checkpoint', "AtUtc"=e."AtUtc"
                FROM audit_controls c JOIN execution_events e ON e."AuditId"=c."AuditId" AND e."Kind"='PluginCompleted' AND e."Detail"=c."PluginId"
                WHERE o."AuditId"=c."AuditId" AND o."Sequence"=c."Sequence";
                UPDATE findings f SET
                  "FirstSeenAtUtc"=(SELECT min(o."AtUtc") FROM finding_observations o WHERE o."ProjectId"=f."ProjectId" AND o."Fingerprint"=f."Fingerprint" AND o."State"='Failed'),
                  "LastSeenAtUtc"=(SELECT max(o."AtUtc") FROM finding_observations o WHERE o."ProjectId"=f."ProjectId" AND o."Fingerprint"=f."Fingerprint" AND o."State"='Failed'),
                  "LastAssessedAtUtc"=(SELECT max(o."AtUtc") FROM finding_observations o WHERE o."ProjectId"=f."ProjectId" AND o."Fingerprint"=f."Fingerprint");
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "TimeSource",
                table: "finding_observations");
        }
    }
}
