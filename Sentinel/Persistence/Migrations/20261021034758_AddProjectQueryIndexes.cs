using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddProjectQueryIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_projects_OrganizationId",
                table: "projects");

            migrationBuilder.CreateIndex(
                name: "IX_projects_OrganizationId_CreatedAtUtc_Id",
                table: "projects",
                columns: new[] { "OrganizationId", "CreatedAtUtc", "Id" });

            migrationBuilder.CreateIndex(
                name: "IX_projects_OrganizationId_Name_Id",
                table: "projects",
                columns: new[] { "OrganizationId", "Name", "Id" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_projects_OrganizationId_CreatedAtUtc_Id",
                table: "projects");

            migrationBuilder.DropIndex(
                name: "IX_projects_OrganizationId_Name_Id",
                table: "projects");

            migrationBuilder.CreateIndex(
                name: "IX_projects_OrganizationId",
                table: "projects",
                column: "OrganizationId");
        }
    }
}
