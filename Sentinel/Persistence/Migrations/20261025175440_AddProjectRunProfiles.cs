using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddProjectRunProfiles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "project_run_profiles",
                columns: table => new
                {
                    ProjectId = table.Column<Guid>(type: "uuid", nullable: false),
                    Version = table.Column<int>(type: "integer", nullable: false),
                    ConfigurationJson = table.Column<string>(type: "jsonb", nullable: false),
                    UpdatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedBy = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_project_run_profiles", x => x.ProjectId);
                    table.ForeignKey(
                        name: "FK_project_run_profiles_projects_ProjectId",
                        column: x => x.ProjectId,
                        principalTable: "projects",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "project_run_profiles");
        }
    }
}
