using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddOrganizationsAndTenantIsolation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "OrganizationId",
                table: "projects",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("a594dfb1-5bee-4d9b-bb65-949f9c0ed0c7"));

            migrationBuilder.CreateTable(
                name: "organizations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_organizations", x => x.Id);
                });

            migrationBuilder.InsertData(
                table: "organizations",
                columns: new[] { "Id", "CreatedAtUtc", "Name" },
                values: new object[] { new Guid("a594dfb1-5bee-4d9b-bb65-949f9c0ed0c7"), new DateTimeOffset(new DateTime(2026, 10, 19, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), "Workspace Sentinel" });

            migrationBuilder.CreateIndex(
                name: "IX_projects_OrganizationId",
                table: "projects",
                column: "OrganizationId");

            migrationBuilder.AddForeignKey(
                name: "FK_audit_outbox_audits_Id",
                table: "audit_outbox",
                column: "Id",
                principalTable: "audits",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_projects_organizations_OrganizationId",
                table: "projects",
                column: "OrganizationId",
                principalTable: "organizations",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_audit_outbox_audits_Id",
                table: "audit_outbox");

            migrationBuilder.DropForeignKey(
                name: "FK_projects_organizations_OrganizationId",
                table: "projects");

            migrationBuilder.DropTable(
                name: "organizations");

            migrationBuilder.DropIndex(
                name: "IX_projects_OrganizationId",
                table: "projects");

            migrationBuilder.DropColumn(
                name: "OrganizationId",
                table: "projects");
        }
    }
}
