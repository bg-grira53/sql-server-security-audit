namespace SqlServerSecurityAudit.Security
{
    public interface IAdminPasswordTester
    {
        /// <summary>
        /// Tests given password against all local administrator accounts.
        /// </summary>
        AdminPasswordCheckResult Test(string password);
    }
}