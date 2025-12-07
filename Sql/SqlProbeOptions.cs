namespace SqlServerSecurityAudit.Sql
{
    public class SqlProbeOptions
    {
        /// <summary>
        /// If false, no network connections to SQL Server should be made.
        /// </summary>
        public bool EnableActiveChecks { get; set; } = true;

        /// <summary>
        /// Reserved for future use (xp_cmdshell toggling).
        /// </summary>
        public bool AllowXpCmdShellToggle { get; set; } = false;

        /// <summary>
        /// Reserved for future use (Ole Automation toggling).
        /// </summary>
        public bool AllowOleAutomationToggle { get; set; } = false;
    }
}