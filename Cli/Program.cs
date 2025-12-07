using System;
using SqlServerSecurityAudit.FileScanning;
using SqlServerSecurityAudit.Pipeline;
using SqlServerSecurityAudit.Reporting;
using SqlServerSecurityAudit.Security;
using SqlServerSecurityAudit.Sql;

namespace SqlServerSecurityAudit.Cli
{
    internal static class Program
    {
        public static int Main(string[] args)
        {
            const string Version = "0.1.0";

            Console.WriteLine($"SqlServerSecurityAudit v{Version}");
            Console.WriteLine("Author / Maintainer: https://github.com/defsecapp");
            Console.WriteLine("Website: https://defsec.app");
            try
            {
                if (args != null &&
                    args.Length > 0 &&
                    (string.Equals(args[0], "-help", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(args[0], "/help", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(args[0], "-?", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(args[0], "/?", StringComparison.OrdinalIgnoreCase)))
                {
                    AppOptionsParser.PrintHelp();
                    return 0;
                }

                var options = AppOptionsParser.Parse(args);

                var fileScanner = new ConfigFileScanner();
                var contentExtractor = new ConfigContentExtractor();
                var connectionGrouper = new ConnectionGrouper();
                var sqlProbe = new SqlProbe();
                var credentialGrouper = new CredentialGrouper();
                var reportWriter = new TextReportWriter();

                IAdminPasswordTester adminPasswordTester = null;
                if (options.EnableAdminPasswordReuseCheck)
                {
                    adminPasswordTester = new AdminPasswordTester();
                }

                var reportOptions = new ReportOptions
                {
                    FilePath = options.GetOutputPath(),
                    IncludePlaintextPasswords = options.IncludePasswordsInReport
                };

                var pipeline = new AuditPipeline(
                    options,
                    fileScanner,
                    contentExtractor,
                    connectionGrouper,
                    sqlProbe,
                    credentialGrouper,
                    adminPasswordTester,
                    reportWriter,
                    reportOptions);

                Console.WriteLine("Starting audit...");
                pipeline.Run();
                Console.WriteLine("Audit finished.");

                return 0;
            }
            catch (OperationCanceledException)
            {
                // e.g. help requested
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Fatal error: " + ex.Message);
                return 1;
            }
        }
    }
}
