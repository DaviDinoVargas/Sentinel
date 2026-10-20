using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddScopeRevocationLifecycle : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "CreatedBy",
                table: "scopes",
                type: "character varying(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RevocationReason",
                table: "scopes",
                type: "character varying(1000)",
                maxLength: 1000,
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "RevokedAtUtc",
                table: "scopes",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RevokedBy",
                table: "scopes",
                type: "character varying(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "scope_events",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ScopeId = table.Column<Guid>(type: "uuid", nullable: false),
                    Kind = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    Actor = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Reason = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: false),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_scope_events", x => x.Id);
                    table.ForeignKey(
                        name: "FK_scope_events_scopes_ScopeId",
                        column: x => x.ScopeId,
                        principalTable: "scopes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_scope_events_ScopeId_CreatedAtUtc_Id",
                table: "scope_events",
                columns: new[] { "ScopeId", "CreatedAtUtc", "Id" });
            migrationBuilder.Sql("""
                CREATE FUNCTION sentinel_scope_events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    RAISE EXCEPTION 'scope_events is append-only';
                END;
                $$;
                CREATE TRIGGER scope_events_append_only BEFORE UPDATE OR DELETE ON scope_events
                FOR EACH ROW EXECUTE FUNCTION sentinel_scope_events_append_only();
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "scope_events");
            migrationBuilder.Sql("DROP FUNCTION sentinel_scope_events_append_only();");

            migrationBuilder.DropColumn(
                name: "CreatedBy",
                table: "scopes");

            migrationBuilder.DropColumn(
                name: "RevocationReason",
                table: "scopes");

            migrationBuilder.DropColumn(
                name: "RevokedAtUtc",
                table: "scopes");

            migrationBuilder.DropColumn(
                name: "RevokedBy",
                table: "scopes");
        }
    }
}
