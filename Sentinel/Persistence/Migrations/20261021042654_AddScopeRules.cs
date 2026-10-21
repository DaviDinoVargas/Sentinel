using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddScopeRules : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "RulesJson",
                table: "scopes",
                type: "character varying(32000)",
                maxLength: 32000,
                nullable: true);
            // Preserve only login POSTs that were explicitly configured before this policy version.
            migrationBuilder.Sql("""
                UPDATE scopes s SET "RulesJson" = json_build_object(
                    'StartsAtUtc', null, 'Methods', CASE WHEN EXISTS (
                        SELECT 1 FROM target_credentials c WHERE c."ScopeId" = s."Id" AND c."CredentialType" = 'JsonLogin'
                    ) THEN '["GET","POST"]'::json ELSE '["GET"]'::json END,
                    'Actions', '["simulated","lab-active","authenticated-lab"]'::json, 'Exclusions', '[]'::json)::text
                WHERE s."Environment" <> 'source-analysis';
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RulesJson",
                table: "scopes");
        }
    }
}
