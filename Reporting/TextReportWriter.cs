using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using SqlServerSecurityAudit.Core.Models;

namespace SqlServerSecurityAudit.Reporting
{
    public class TextReportWriter : IReportWriter
    {
        public void WriteReport(AuditReportInput input, ReportOptions options)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (options == null) throw new ArgumentNullException(nameof(options));

            var filePath = options.FilePath
                           ?? throw new ArgumentException("ReportOptions.FilePath must be set.", nameof(options));

            Directory.CreateDirectory(Path.GetDirectoryName(filePath) ?? ".");

            using (var writer = new StreamWriter(filePath, false, Encoding.UTF8))
            {
                WriteHeader(writer, input);
                WriteCredentialGroupsSection(writer, input.CredentialGroups, options);
                WriteExtraPasswordCandidatesSection(writer, input.PasswordCandidates);
                writer.WriteLine("=== End of report ===");
            }
        }

        private static void WriteHeader(StreamWriter writer, AuditReportInput input)
        {
            writer.WriteLine("=== SQL Server security audit report ===");
            writer.WriteLine("Timestamp: {0}", input.Timestamp);
            writer.WriteLine("Root scope: {0}", string.IsNullOrEmpty(input.RootDescription)
                ? "<unknown>"
                : input.RootDescription);
            writer.WriteLine("Total credential groups: {0}", input.CredentialGroups?.Count ?? 0);
            writer.WriteLine();
        }

        private static void WriteCredentialGroupsSection(
            StreamWriter writer,
            IList<CredentialGroup> credentialGroups,
            ReportOptions options)
        {
            if (credentialGroups == null || credentialGroups.Count == 0)
            {
                writer.WriteLine("No successful SQL credential groups were discovered.");
                writer.WriteLine();
                return;
            }

            writer.WriteLine("=== SQL Server command execution surface (grouped by server-login-password) ===");
            writer.WriteLine();

            foreach (var group in credentialGroups)
            {
                if (group == null)
                    continue;

                var representative = group.Members != null && group.Members.Count > 0
                    ? group.Members[0]
                    : null;

                writer.WriteLine("------------------------------------------------------------");
                writer.WriteLine("Server data source: {0}",
                    string.IsNullOrEmpty(group.ServerDataSource) ? "<unknown>" : group.ServerDataSource);
                writer.WriteLine("Login: {0}", group.LoginDisplay ?? "<unknown>");

                var passwordForReport = FormatPasswordForReport(group, options);
                writer.WriteLine("Password: {0}", passwordForReport);
                writer.WriteLine("Uses Windows auth: {0}", group.IsWindowsAuth ? "yes" : "no");

                if (representative != null)
                {
                    writer.WriteLine("Actual SYSTEM_USER (inside SQL): {0}",
                        string.IsNullOrEmpty(representative.ActualSystemUser)
                            ? "<unknown>"
                            : representative.ActualSystemUser);

                    writer.WriteLine("Actual ORIGINAL_LOGIN() (inside SQL): {0}",
                        string.IsNullOrEmpty(representative.ActualOriginalLogin)
                            ? "<unknown>"
                            : representative.ActualOriginalLogin);

                    writer.WriteLine("Example successful connection string:");
                    writer.WriteLine(string.IsNullOrEmpty(representative.SuccessfulConnectionString)
                        ? "<unknown>"
                        : representative.SuccessfulConnectionString);

                    WriteAdminReuseSection(writer, group);
                    WriteLocationsSection(writer, group, representative);
                    WriteSqlServiceAccountSection(writer, representative);
                    WriteCommandExecutionSection(writer, representative);
                    WriteSqlAgentSection(writer, representative);
                    WriteLinkedServersSection(writer, representative);

                    if (!string.IsNullOrEmpty(representative.ErrorMessage))
                    {
                        writer.WriteLine();
                        writer.WriteLine("Details: {0}", representative.ErrorMessage);
                    }
                }
                else
                {
                    writer.WriteLine("No representative connection result is available for this group.");
                }

                writer.WriteLine();
            }
        }

        private static string FormatPasswordForReport(CredentialGroup group, ReportOptions options)
        {
            if (group.IsWindowsAuth)
                return "<windows>";

            if (string.IsNullOrEmpty(group.PasswordRaw))
            {
                return "<empty>";
            }

            if (!options.IncludePlaintextPasswords)
            {
                return "******** (redacted)";
            }

            return group.PasswordRaw;
        }

        private static void WriteAdminReuseSection(StreamWriter writer, CredentialGroup group)
        {
            if (!group.AdminPasswordTested)
            {
                writer.WriteLine("Password tested against local administrators: not tested");
                return;
            }

            writer.WriteLine("Password matches at least one local Administrator account: {0}",
                group.AdminPasswordMatchesAnyLocalAdmin ? "YES (CRITICAL)" : "no");

            if (group.AdminPasswordMatchesAnyLocalAdmin &&
                !string.IsNullOrEmpty(group.AdminMatchedAccounts))
            {
                writer.WriteLine("Matched admin account(s): {0}", group.AdminMatchedAccounts);
            }
        }

        private static void WriteLocationsSection(
            StreamWriter writer,
            CredentialGroup group,
            ConnectionCheckResult representative)
        {
            writer.WriteLine("Found in {0} location(s):", group.FilePaths.Count);
            foreach (var path in group.FilePaths.OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
            {
                writer.WriteLine("  - {0}", path);
            }

            writer.WriteLine("SQL Server IP: {0}",
                string.IsNullOrEmpty(representative.ServerIpAddress)
                    ? "<unknown>"
                    : representative.ServerIpAddress);

            string location;
            if (!representative.IsLocalServer.HasValue)
            {
                location = "unknown";
            }
            else
            {
                location = representative.IsLocalServer.Value ? "local (same machine)" : "remote";
            }

            writer.WriteLine("SQL Server location: {0}", location);
        }

        private static void WriteSqlServiceAccountSection(StreamWriter writer, ConnectionCheckResult representative)
        {
            writer.WriteLine("SQL Server service account: {0}",
                string.IsNullOrEmpty(representative.SqlServiceAccount)
                    ? "<unknown>"
                    : representative.SqlServiceAccount);

            string isDomainAcc = !representative.SqlServiceAccountIsDomainAccount.HasValue
                ? "unknown"
                : (representative.SqlServiceAccountIsDomainAccount.Value ? "yes" : "no");
            writer.WriteLine("Service account is domain account: {0}", isDomainAcc);

            string isDomainAdmin = !representative.SqlServiceAccountIsDomainAdmin.HasValue
                ? "unknown"
                : (representative.SqlServiceAccountIsDomainAdmin.Value ? "YES (CRITICAL)" : "no");
            writer.WriteLine("Service account is Domain Admin: {0}", isDomainAdmin);
        }

        private static void WriteCommandExecutionSection(StreamWriter writer, ConnectionCheckResult representative)
        {
            writer.WriteLine("xp_cmdshell whoami: {0}",
                representative.XpCmdShellSuccess ? "SUCCESS" : "ERROR or not available");
            if (representative.XpCmdShellSuccess)
            {
                writer.WriteLine("xp_cmdshell whoami output: {0}",
                    string.IsNullOrEmpty(representative.XpCmdShellWhoAmI)
                        ? "<empty>"
                        : representative.XpCmdShellWhoAmI);
            }

            writer.WriteLine("OLE Automation whoami tried: {0}",
                representative.OleAutomationTried ? "yes" : "no");
            if (representative.OleAutomationTried)
            {
                if (representative.OleAutomationWhoAmISuccess)
                {
                    writer.WriteLine("OLE Automation whoami: SUCCESS");
                    writer.WriteLine("OLE Automation whoami output: {0}",
                        string.IsNullOrEmpty(representative.OleAutomationWhoAmI)
                            ? "<empty>"
                            : representative.OleAutomationWhoAmI);
                }
                else
                {
                    writer.WriteLine("OLE Automation whoami: ERROR or not available");
                }
            }

            writer.WriteLine("External scripts enabled: {0}",
                representative.ExternalScriptsEnabled ? "yes" : "no");
            if (representative.ExternalScriptsEnabled)
            {
                if (representative.ExternalScriptsWhoAmISuccess)
                {
                    writer.WriteLine("External scripts whoami: SUCCESS via {0}",
                        string.IsNullOrEmpty(representative.ExternalScriptsLanguage)
                            ? "<unknown>"
                            : representative.ExternalScriptsLanguage);
                    writer.WriteLine("External scripts whoami output: {0}",
                        string.IsNullOrEmpty(representative.ExternalScriptsWhoAmI)
                            ? "<empty>"
                            : representative.ExternalScriptsWhoAmI);
                }
                else
                {
                    writer.WriteLine("External scripts whoami: ERROR (R/Python failed or not installed)");
                }
            }
        }

        private static void WriteSqlAgentSection(StreamWriter writer, ConnectionCheckResult representative)
        {
            if (!representative.SqlAgentSurfaceChecked)
                return;

            writer.WriteLine("SQL Agent CmdExec surface present: {0}",
                representative.SqlAgentCmdExecSurfacePresent ? "YES" : "NO");
            if (representative.SqlAgentCmdExecSurfacePresent)
            {
                writer.WriteLine("SQL Agent CmdExec steps count: {0}",
                    representative.SqlAgentCmdExecJobStepCount);
                writer.WriteLine("SQL Agent roles: {0}",
                    string.IsNullOrEmpty(representative.SqlAgentRoles)
                        ? "<unknown>"
                        : representative.SqlAgentRoles);
            }
        }

        private static void WriteLinkedServersSection(StreamWriter writer, ConnectionCheckResult representative)
        {
            if (!representative.LinkedServersChecked)
                return;

            writer.WriteLine("Linked servers with RPC OUT: {0}",
                representative.LinkedServersRpcOutCount);
        }

        private static void WriteExtraPasswordCandidatesSection(
            StreamWriter writer,
            List<PasswordCandidate> allPasswordCandidates)
        {
            writer.WriteLine("=== Extra password attributes with 'passw' checked against local administrators ===");
            writer.WriteLine();

            if (allPasswordCandidates == null || allPasswordCandidates.Count == 0)
            {
                writer.WriteLine("No password-like attributes were discovered.");
                writer.WriteLine();
                return;
            }

            var interestingCandidates = allPasswordCandidates
                .Where(c => c.AdminPasswordTested && c.AdminPasswordMatchesAnyLocalAdmin)
                .OrderBy(c => c.PasswordValue, StringComparer.Ordinal)
                .ThenBy(c => c.FilePath, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (interestingCandidates.Count == 0)
            {
                writer.WriteLine("No additional passwords from 'passw*' attributes matched any local administrator account.");
                writer.WriteLine();
                return;
            }

            writer.WriteLine("Total matching password attributes: {0}", interestingCandidates.Count);
            writer.WriteLine();

            foreach (var c in interestingCandidates)
            {
                writer.WriteLine("------------------------------------------------------------");
                writer.WriteLine("File: {0}", c.FilePath);
                writer.WriteLine("Attribute name: {0}", c.AttributeName);
                writer.WriteLine("Password value: {0}", c.PasswordValue);
                writer.WriteLine("Source line snippet: {0}", c.SourceSnippet ?? "<none>");
                writer.WriteLine("Matches local admin account(s): {0}",
                    string.IsNullOrEmpty(c.AdminMatchedAccounts)
                        ? "<unknown>"
                        : c.AdminMatchedAccounts);

                if (!string.IsNullOrEmpty(c.AdminPasswordCheckError))
                {
                    writer.WriteLine("Admin password check details: {0}", c.AdminPasswordCheckError);
                }

                writer.WriteLine();
            }
        }
    }
}
