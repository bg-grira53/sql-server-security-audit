namespace SqlServerSecurityAudit.Reporting
{
    public class ReportOptions
    {
        /// <summary>
        /// Full path to the output report file.
        /// </summary>
        public string FilePath { get; set; }

        /// <summary>
        /// If false, real passwords will be redacted in the report.
        /// </summary>
        public bool IncludePlaintextPasswords { get; set; } = false;
    }
}