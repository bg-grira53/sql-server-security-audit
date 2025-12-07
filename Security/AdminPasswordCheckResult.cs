namespace SqlServerSecurityAudit.Security
{
    public class AdminPasswordCheckResult
    {
        public bool Success { get; set; }
        public string MatchedAccounts { get; set; }
        public string Error { get; set; }
    }
}