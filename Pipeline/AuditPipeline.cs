using SqlServerSecurityAudit.Cli;
using SqlServerSecurityAudit.Core.Models;
using SqlServerSecurityAudit.FileScanning;
using SqlServerSecurityAudit.Security;
using SqlServerSecurityAudit.Sql;
using SqlServerSecurityAudit.Reporting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SqlServerSecurityAudit.Pipeline
{
    public class AuditPipeline
    {
        private readonly AppOptions _options;
        private readonly IConfigFileScanner _fileScanner;
        private readonly IConfigContentExtractor _contentExtractor;
        private readonly IConnectionGrouper _connectionGrouper;
        private readonly ISqlProbe _sqlProbe;
        private readonly ICredentialGrouper _credentialGrouper;
        private readonly IAdminPasswordTester _adminPasswordTester;
        private readonly IReportWriter _reportWriter;
        private readonly ReportOptions _reportOptions;

        public AuditPipeline(
            AppOptions options,
            IConfigFileScanner fileScanner,
            IConfigContentExtractor contentExtractor,
            IConnectionGrouper connectionGrouper,
            ISqlProbe sqlProbe,
            ICredentialGrouper credentialGrouper,
            IAdminPasswordTester adminPasswordTester,
            IReportWriter reportWriter,
            ReportOptions reportOptions)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _fileScanner = fileScanner ?? throw new ArgumentNullException(nameof(fileScanner));
            _contentExtractor = contentExtractor ?? throw new ArgumentNullException(nameof(contentExtractor));
            _connectionGrouper = connectionGrouper ?? throw new ArgumentNullException(nameof(connectionGrouper));
            _sqlProbe = sqlProbe ?? throw new ArgumentNullException(nameof(sqlProbe));
            _credentialGrouper = credentialGrouper ?? throw new ArgumentNullException(nameof(credentialGrouper));
            _adminPasswordTester = adminPasswordTester;
            _reportWriter = reportWriter ?? throw new ArgumentNullException(nameof(reportWriter));
            _reportOptions = reportOptions ?? throw new ArgumentNullException(nameof(reportOptions));
        }

        public void Run()
        {
            var roots = ResolveRootDirectories();

            if (roots.Count == 0)
            {
                Console.WriteLine("No root directories to scan. Nothing to do.");
                return;
            }

            Console.WriteLine("Roots to scan:");
            foreach (var r in roots)
            {
                Console.WriteLine("  - {0}", r);
            }
            Console.WriteLine();

            var allConnectionInfos = new List<ConnectionInfo>();
            var allPasswordCandidates = new List<PasswordCandidate>();

            Console.WriteLine("Enumerating configuration files...");
            var configFiles = _fileScanner.EnumerateConfigFiles(roots);

            int fileCount = 0;
            foreach (var filePath in configFiles)
            {
                fileCount++;
                Console.WriteLine("[{0}] {1}", fileCount, filePath);

                try
                {
                    var analysis = _contentExtractor.Extract(filePath);

                    if (analysis.Connections.Count > 0)
                        allConnectionInfos.AddRange(analysis.Connections);

                    if (analysis.PasswordCandidates.Count > 0)
                        allPasswordCandidates.AddRange(analysis.PasswordCandidates);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error while processing file {0}: {1}", filePath, ex.Message);
                }
            }

            Console.WriteLine();
            Console.WriteLine("Total configuration files processed: {0}", fileCount);
            Console.WriteLine("Total raw connection strings found (after filtering): {0}", allConnectionInfos.Count);
            Console.WriteLine("Total password-like attributes found: {0}", allPasswordCandidates.Count);
            Console.WriteLine();

            var connectionResults = new List<ConnectionCheckResult>();

            if (_options.EnableSqlActiveChecks && allConnectionInfos.Count > 0)
            {
                RunSqlProbes(allConnectionInfos, connectionResults);
            }
            else
            {
                Console.WriteLine("Active SQL checks are disabled or there are no connection strings to probe.");
            }

            // Group by (server, login, password)
            var credentialGroups = _credentialGrouper.GroupByCredentials(connectionResults);

            Console.WriteLine();
            Console.WriteLine("Total successful credential groups: {0}", credentialGroups.Count);

            // Admin password reuse checks
            if (_options.EnableAdminPasswordReuseCheck && credentialGroups.Count > 0)
            {
                RunAdminPasswordReuseChecks(credentialGroups, allPasswordCandidates);
            }
            else
            {
                Console.WriteLine("Admin password reuse checks are disabled or there are no successful credentials.");
            }

            Console.WriteLine();
            Console.WriteLine("Generating report...");

            var reportInput = new AuditReportInput
            {
                Timestamp = DateTime.Now,
                RootDescription = BuildRootDescription(roots),
                CredentialGroups = credentialGroups,
                PasswordCandidates = allPasswordCandidates
            };

            _reportWriter.WriteReport(reportInput, _reportOptions);

            Console.WriteLine("Report written to: {0}", _reportOptions.FilePath);
            Console.WriteLine();
            Console.WriteLine("Audit pipeline finished.");


        }

        private static string BuildRootDescription(List<string> roots)
        {
            if (roots == null || roots.Count == 0)
                return "<none>";

            if (roots.Count == 1)
                return roots[0];

            return string.Join(", ", roots);
        }


        private void RunSqlProbes(
            List<ConnectionInfo> allConnectionInfos,
            List<ConnectionCheckResult> connectionResults)
        {
            Console.WriteLine("Grouping connections by server and login...");
            var serverGroups = _connectionGrouper.GroupByServerAndLogin(allConnectionInfos);

            int totalServers = serverGroups.Count;
            int totalGroups = serverGroups.Values.Sum(list => list.Count);

            Console.WriteLine("Distinct servers: {0}", totalServers);
            Console.WriteLine("Distinct (server, login) pairs: {0}", totalGroups);
            Console.WriteLine();

            var probeOptions = new SqlProbeOptions
            {
                EnableActiveChecks = true,
                AllowXpCmdShellToggle = _options.EnableXpCmdShellToggle,
                AllowOleAutomationToggle = _options.EnableOleAutomationToggle
            };

            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = Math.Max(2, Environment.ProcessorCount)
            };

            int serverCounter = 0;
            object resultsLock = new object();

            Parallel.ForEach(serverGroups, parallelOptions, serverEntry =>
            {
                string serverKey = serverEntry.Key;
                var userGroups = serverEntry.Value;

                int currentServerIndex = Interlocked.Increment(ref serverCounter);
                Console.WriteLine("[Server {0}/{1}] {2}", currentServerIndex, totalServers, serverKey);

                foreach (var group in userGroups)
                {
                    var representative = group.Representative;

                    Console.WriteLine("  Probing login '{0}' using file: {1}",
                        group.LoginKey, representative.FilePath);

                    var probeResult = _sqlProbe.Probe(representative, probeOptions);

                    lock (resultsLock)
                    {
                        foreach (var info in group.Connections)
                        {
                            var cloned = CloneResultForConnection(probeResult, info);
                            connectionResults.Add(cloned);
                        }
                    }
                }
            });

            Console.WriteLine();
            Console.WriteLine("Total connection results: {0}", connectionResults.Count);
            Console.WriteLine("Successful connections: {0}", connectionResults.Count(r => r.ConnectionSuccess));
        }

        private static ConnectionCheckResult CloneResultForConnection(
            ConnectionCheckResult template,
            ConnectionInfo connection)
        {
            return new ConnectionCheckResult
            {
                Connection = connection,

                ConnectionSuccess = template.ConnectionSuccess,
                ActualSystemUser = template.ActualSystemUser,
                ActualOriginalLogin = template.ActualOriginalLogin,
                SuccessfulConnectionString = template.SuccessfulConnectionString,

                XpCmdShellSuccess = template.XpCmdShellSuccess,
                XpCmdShellWhoAmI = template.XpCmdShellWhoAmI,

                OleAutomationTried = template.OleAutomationTried,
                OleAutomationWhoAmISuccess = template.OleAutomationWhoAmISuccess,
                OleAutomationWhoAmI = template.OleAutomationWhoAmI,

                ExternalScriptsEnabled = template.ExternalScriptsEnabled,
                ExternalScriptsWhoAmISuccess = template.ExternalScriptsWhoAmISuccess,
                ExternalScriptsLanguage = template.ExternalScriptsLanguage,
                ExternalScriptsWhoAmI = template.ExternalScriptsWhoAmI,

                SqlAgentSurfaceChecked = template.SqlAgentSurfaceChecked,
                SqlAgentCmdExecSurfacePresent = template.SqlAgentCmdExecSurfacePresent,
                SqlAgentCmdExecJobStepCount = template.SqlAgentCmdExecJobStepCount,
                SqlAgentRoles = template.SqlAgentRoles,

                LinkedServersChecked = template.LinkedServersChecked,
                LinkedServersRpcOutPresent = template.LinkedServersRpcOutPresent,
                LinkedServersRpcOutCount = template.LinkedServersRpcOutCount,

                SqlServiceAccount = template.SqlServiceAccount,
                SqlServiceAccountIsDomainAccount = template.SqlServiceAccountIsDomainAccount,
                SqlServiceAccountIsDomainAdmin = template.SqlServiceAccountIsDomainAdmin,
                SqlServiceAccountCheckError = template.SqlServiceAccountCheckError,

                ServerDataSource = template.ServerDataSource,
                ServerIpAddress = template.ServerIpAddress,
                IsLocalServer = template.IsLocalServer,

                ErrorMessage = template.ErrorMessage
            };
        }

        private List<string> ResolveRootDirectories()
        {
            var roots = new List<string>();

            if (_options.RootDirectories.Count > 0)
            {
                roots.AddRange(_options.RootDirectories);
                return roots;
            }

            if (!_options.ScanAllDrivesIfNoRootSpecified)
            {
                return roots;
            }

            try
            {
                foreach (var drive in System.IO.DriveInfo.GetDrives())
                {
                    if (!drive.IsReady)
                        continue;

                    if (drive.DriveType == System.IO.DriveType.CDRom)
                        continue;

                    if (drive.Name.StartsWith("A:", StringComparison.OrdinalIgnoreCase) ||
                        drive.Name.StartsWith("B:", StringComparison.OrdinalIgnoreCase))
                        continue;

                    roots.Add(drive.RootDirectory.FullName);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error while enumerating drives: {0}", ex.Message);
            }

            return roots;
        }

        private void RunAdminPasswordReuseChecks(
    IList<CredentialGroup> credentialGroups,
    List<PasswordCandidate> allPasswordCandidates)
        {
            if (_adminPasswordTester == null)
            {
                Console.WriteLine("Admin password reuse checks are disabled.");
                return;
            }

            Console.WriteLine();
            Console.WriteLine("Running admin password reuse checks...");

            // 1) Credential groups (from connection strings)
            foreach (var group in credentialGroups)
            {
                group.AdminPasswordTested = false;
                group.AdminPasswordMatchesAnyLocalAdmin = false;
                group.AdminMatchedAccounts = null;
                group.AdminPasswordCheckError = null;

                if (group.IsWindowsAuth)
                    continue;

                var pwd = group.PasswordRaw;
                if (string.IsNullOrEmpty(pwd))
                    continue;

                var check = _adminPasswordTester.Test(pwd);

                group.AdminPasswordTested = true;
                group.AdminPasswordMatchesAnyLocalAdmin = check.Success;
                group.AdminMatchedAccounts = check.MatchedAccounts;
                group.AdminPasswordCheckError = check.Error;
            }

            // 2) Password candidates (from arbitrary "passw*" attributes)
            foreach (var candidate in allPasswordCandidates)
            {
                candidate.AdminPasswordTested = false;
                candidate.AdminPasswordMatchesAnyLocalAdmin = false;
                candidate.AdminMatchedAccounts = null;
                candidate.AdminPasswordCheckError = null;

                var pwd = candidate.PasswordValue;
                if (string.IsNullOrEmpty(pwd))
                    continue;

                var check = _adminPasswordTester.Test(pwd);

                candidate.AdminPasswordTested = true;
                candidate.AdminPasswordMatchesAnyLocalAdmin = check.Success;
                candidate.AdminMatchedAccounts = check.MatchedAccounts;
                candidate.AdminPasswordCheckError = check.Error;
            }

            Console.WriteLine("Admin password reuse checks completed.");
        }

    }
}
