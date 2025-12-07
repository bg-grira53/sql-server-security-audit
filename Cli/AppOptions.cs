using System;
using System.Collections.Generic;
using System.IO;

namespace SqlServerSecurityAudit.Cli
{
    public class AppOptions
    {
        public List<string> RootDirectories { get; } = new List<string>();

        // If true and no explicit roots provided, scan all suitable drives
        public bool ScanAllDrivesIfNoRootSpecified { get; set; } = true;

        // Active checks on SQL Server (connecting, querying, etc.)
        // Default: enabled, but without changing server configuration.
        public bool EnableSqlActiveChecks { get; set; } = true;

        // Allow toggling xp_cmdshell and Ole Automation
        // Default: disabled (must be explicitly enabled).
        public bool EnableXpCmdShellToggle { get; set; } = false;
        public bool EnableOleAutomationToggle { get; set; } = false;

        // Try passwords against local administrator accounts
        // Default: disabled (must be explicitly enabled).
        public bool EnableAdminPasswordReuseCheck { get; set; } = false;

        // Include raw passwords in the text report
        public bool IncludePasswordsInReport { get; set; } = false;

        // Output file name (without path)
        public string OutputFileName { get; set; } = "sqlout.txt";

        public string GetOutputPath()
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, OutputFileName);
        }
    }
}