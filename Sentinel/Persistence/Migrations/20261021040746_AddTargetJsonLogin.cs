using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Sentinel.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddTargetJsonLogin : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "CredentialType",
                table: "target_credentials",
                type: "character varying(20)",
                maxLength: 20,
                nullable: false,
                defaultValue: "Bearer");

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LastLoginAtUtc",
                table: "target_credentials",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LastLoginStatus",
                table: "target_credentials",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LoginConfigurationJson",
                table: "target_credentials",
                type: "character varying(4000)",
                maxLength: 4000,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "target_credential_events",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    CredentialId = table.Column<Guid>(type: "uuid", nullable: false),
                    Version = table.Column<int>(type: "integer", nullable: false),
                    Kind = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Actor = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    AuditId = table.Column<Guid>(type: "uuid", nullable: true),
                    AtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_target_credential_events", x => x.Id);
                    table.ForeignKey(
                        name: "FK_target_credential_events_target_credentials_CredentialId",
                        column: x => x.CredentialId,
                        principalTable: "target_credentials",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_target_credential_events_CredentialId_Id",
                table: "target_credential_events",
                columns: new[] { "CredentialId", "Id" });
            migrationBuilder.Sql("""
                CREATE FUNCTION sentinel_credential_events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'target_credential_events is append-only'; END; $$;
                CREATE TRIGGER target_credential_events_append_only BEFORE UPDATE OR DELETE ON target_credential_events
                FOR EACH ROW EXECUTE FUNCTION sentinel_credential_events_append_only();
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "target_credential_events");
            migrationBuilder.Sql("DROP FUNCTION sentinel_credential_events_append_only();");

            migrationBuilder.DropColumn(
                name: "CredentialType",
                table: "target_credentials");

            migrationBuilder.DropColumn(
                name: "LastLoginAtUtc",
                table: "target_credentials");

            migrationBuilder.DropColumn(
                name: "LastLoginStatus",
                table: "target_credentials");

            migrationBuilder.DropColumn(
                name: "LoginConfigurationJson",
                table: "target_credentials");
        }
    }
}
