namespace SqlServerSecurityAudit.Reporting
{
    public interface IReportWriter
    {
        void WriteReport(AuditReportInput input, ReportOptions options);
    }
}