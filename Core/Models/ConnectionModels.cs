using System.Collections.Generic;

namespace SqlServerSecurityAudit.Core.Models
{
    public class ConnectionInfo
    {
        public string FilePath { get; set; }
        public string ConnectionString { get; set; }
        public string SourceSnippet { get; set; }
    }

    public class ConnectionCheckResult
    {
        public ConnectionInfo Connection { get; set; }

        public bool ConnectionSuccess { get; set; }

        public string ActualSystemUser { get; set; }
        public string ActualOriginalLogin { get; set; }

        public string SuccessfulConnectionString { get; set; }

        // xp_cmdshell
        public bool XpCmdShellSuccess { get; set; }
        public string XpCmdShellWhoAmI { get; set; }

        // OLE Automation (sp_OACreate / WScript.Shell)
        public bool OleAutomationTried { get; set; }
        public bool OleAutomationWhoAmISuccess { get; set; }
        public string OleAutomationWhoAmI { get; set; }

        // External scripts (sp_execute_external_script)
        public bool ExternalScriptsEnabled { get; set; }
        public bool ExternalScriptsWhoAmISuccess { get; set; }
        public string ExternalScriptsLanguage { get; set; } // "R" / "Python"
        public string ExternalScriptsWhoAmI { get; set; }

        // SQL Agent CmdExec surface
        public bool SqlAgentSurfaceChecked { get; set; }
        public bool SqlAgentCmdExecSurfacePresent { get; set; }
        public int SqlAgentCmdExecJobStepCount { get; set; }
        public string SqlAgentRoles { get; set; }

        // Linked servers with RPC OUT
        public bool LinkedServersChecked { get; set; }
        public bool LinkedServersRpcOutPresent { get; set; }
        public int LinkedServersRpcOutCount { get; set; }

        // SQL Server service account
        public string SqlServiceAccount { get; set; }
        public bool? SqlServiceAccountIsDomainAccount { get; set; }
        public bool? SqlServiceAccountIsDomainAdmin { get; set; }
        public string SqlServiceAccountCheckError { get; set; }

        // Server info
        public string ServerDataSource { get; set; }
        public string ServerIpAddress { get; set; }
        public bool? IsLocalServer { get; set; }

        // Aggregated error/info text
        public string ErrorMessage { get; set; }
    }

    public class ServerUserGroup
    {
        public string ServerKey { get; set; }
        public string LoginKey { get; set; }
        public System.Collections.Generic.List<ConnectionInfo> Connections { get; set; }
            = new System.Collections.Generic.List<ConnectionInfo>();

        public ConnectionInfo Representative => Connections[0];
    }

    public class CredentialGroup
    {
        public string ServerDataSource { get; set; }
        public string LoginDisplay { get; set; }          // "sa", "IntegratedSecurity", etc.
        /// <summary>
        /// Raw password value as taken from the connection string.
        /// Will be null for Windows authentication.
        /// </summary>
        public string PasswordRaw { get; set; }

        /// <summary>
        /// Password value intended for reporting (may be masked).
        /// </summary>
        public string PasswordDisplay { get; set; }
        public bool IsWindowsAuth { get; set; }

        public bool AdminPasswordTested { get; set; }
        public bool AdminPasswordMatchesAnyLocalAdmin { get; set; }
        public string AdminMatchedAccounts { get; set; }      // "MACHINE\\Administrator; DOMAIN\\User"
        public string AdminPasswordCheckError { get; set; }   // aggregated error text

        public List<ConnectionCheckResult> Members { get; }
            = new List<ConnectionCheckResult>();

        public HashSet<string> FilePaths { get; }
            = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
    }

    public class PasswordCandidate
    {
        public string FilePath { get; set; }
        public string AttributeName { get; set; }
        public string PasswordValue { get; set; }
        public string SourceSnippet { get; set; }

        public bool AdminPasswordTested { get; set; }
        public bool AdminPasswordMatchesAnyLocalAdmin { get; set; }
        public string AdminMatchedAccounts { get; set; }
        public string AdminPasswordCheckError { get; set; }
    }

    public class AdminAccountInfo
    {
        public string Domain { get; set; }      // MACHINE or DOMAIN
        public string UserName { get; set; }    // samAccountName
        public string DisplayName { get; set; } // for logging
    }

    public class ConfigFileAnalysis
    {
        public List<ConnectionInfo> Connections { get; } = new List<ConnectionInfo>();
        public List<PasswordCandidate> PasswordCandidates { get; } = new List<PasswordCandidate>();
    }
}
