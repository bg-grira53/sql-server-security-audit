using System;
using System.IO;

namespace SqlServerSecurityAudit.Cli
{
    public static class AppOptionsParser
    {
        public static AppOptions Parse(string[] args)
        {
            var options = new AppOptions();

            if (args == null || args.Length == 0)
                return options; // default standard-like behavior

            string profileName = null;

            // First pass: detect profile
            for (int i = 0; i < args.Length; i++)
            {
                var arg = args[i];
                if (arg.Equals("--profile", StringComparison.OrdinalIgnoreCase) ||
                    arg.Equals("-p", StringComparison.OrdinalIgnoreCase))
                {
                    if (i + 1 >= args.Length)
                        throw new ArgumentException("Missing value for --profile.");

                    profileName = args[++i];
                }
            }

            ApplyProfile(profileName, options);

            // Second pass: parse all other arguments and allow overrides
            for (int i = 0; i < args.Length; i++)
            {
                var arg = args[i];

                if (arg.StartsWith("-", StringComparison.Ordinal) ||
                    arg.StartsWith("/", StringComparison.Ordinal))
                {
                    // Normalize to "--xxx" style
                    var key = arg.TrimStart('-', '/');

                    switch (key.ToLowerInvariant())
                    {
                        case "profile":
                        case "p":
                            i++; // already processed in first pass
                            break;

                        case "root":
                            if (i + 1 >= args.Length)
                                throw new ArgumentException("Missing value for --root.");

                            options.RootDirectories.Add(Path.GetFullPath(args[++i]));
                            break;

                        case "no-scan-all":
                            options.ScanAllDrivesIfNoRootSpecified = false;
                            break;

                        case "scan-all":
                            options.ScanAllDrivesIfNoRootSpecified = true;
                            break;

                        case "passive":
                            // Shortcut: equivalent to --profile passive
                            ApplyProfile("passive", options);
                            break;

                        case "active-sql":
                            options.EnableSqlActiveChecks = true;
                            break;

                        case "no-active-sql":
                            options.EnableSqlActiveChecks = false;
                            break;

                        case "xp-toggle":
                            options.EnableXpCmdShellToggle = true;
                            break;

                        case "no-xp-toggle":
                            options.EnableXpCmdShellToggle = false;
                            break;

                        case "ole-toggle":
                            options.EnableOleAutomationToggle = true;
                            break;

                        case "no-ole-toggle":
                            options.EnableOleAutomationToggle = false;
                            break;

                        case "admin-reuse":
                            options.EnableAdminPasswordReuseCheck = true;
                            break;

                        case "no-admin-reuse":
                            options.EnableAdminPasswordReuseCheck = false;
                            break;

                        case "show-passwords":
                            options.IncludePasswordsInReport = true;
                            break;

                        case "no-show-passwords":
                            options.IncludePasswordsInReport = false;
                            break;

                        case "output":
                        case "o":
                            if (i + 1 >= args.Length)
                                throw new ArgumentException("Missing value for --output.");
                            options.OutputFileName = args[++i];
                            break;

                        case "help":
                        case "?":
                            PrintHelp();
                            throw new OperationCanceledException("Help requested.");

                        default:
                            throw new ArgumentException($"Unknown argument: {arg}");
                    }
                }
                else
                {
                    // Treat bare path as a root directory
                    options.RootDirectories.Add(Path.GetFullPath(arg));
                }
            }

            return options;
        }

        private static void ApplyProfile(string profileName, AppOptions options)
        {
            if (string.IsNullOrWhiteSpace(profileName))
                return; // no profile specified, keep defaults (standard-like)

            switch (profileName.ToLowerInvariant())
            {
                case "passive":
                    options.EnableSqlActiveChecks = false;
                    options.EnableXpCmdShellToggle = false;
                    options.EnableOleAutomationToggle = false;
                    options.EnableAdminPasswordReuseCheck = false;
                    break;

                case "standard":
                    options.EnableSqlActiveChecks = true;
                    options.EnableXpCmdShellToggle = false;
                    options.EnableOleAutomationToggle = false;
                    options.EnableAdminPasswordReuseCheck = false;
                    break;

                case "deep":
                    options.EnableSqlActiveChecks = true;
                    options.EnableXpCmdShellToggle = true;
                    options.EnableOleAutomationToggle = true;
                    options.EnableAdminPasswordReuseCheck = true;
                    break;

                default:
                    throw new ArgumentException($"Unknown profile: {profileName}. Expected: passive, standard, deep.");
            }
        }

        public static void PrintHelp()
        {
            Console.WriteLine("SqlServerSecurityAudit - SQL Server configuration and access surface audit");
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("  SqlServerSecurityAudit.exe [options] [root1] [root2] ...");
            Console.WriteLine();
            Console.WriteLine("Profiles:");
            Console.WriteLine("  --profile passive    Passive mode, file-based only, no SQL connections.");
            Console.WriteLine("  --profile standard   Default mode: SQL checks enabled, no config changes.");
            Console.WriteLine("  --profile deep       Aggressive mode: xp_cmdshell/OLE toggle + admin reuse.");
            Console.WriteLine();
            Console.WriteLine("General options:");
            Console.WriteLine("  --root <path>        Add root directory to scan (can be used multiple times).");
            Console.WriteLine("  --scan-all           Scan all suitable drives if no root is specified (default).");
            Console.WriteLine("  --no-scan-all        Do not scan all drives automatically.");
            Console.WriteLine("  --output, -o <file>  Output report file name (default: sqlout.txt).");
            Console.WriteLine();
            Console.WriteLine("SQL checks:");
            Console.WriteLine("  --active-sql         Enable active SQL checks (connect and query).");
            Console.WriteLine("  --no-active-sql      Disable active SQL checks.");
            Console.WriteLine("  --xp-toggle          Allow enabling/disabling xp_cmdshell.");
            Console.WriteLine("  --no-xp-toggle       Do not touch xp_cmdshell configuration (default).");
            Console.WriteLine("  --ole-toggle         Allow enabling/disabling Ole Automation Procedures.");
            Console.WriteLine("  --no-ole-toggle      Do not touch Ole Automation configuration (default).");
            Console.WriteLine();
            Console.WriteLine("Security checks:");
            Console.WriteLine("  --admin-reuse        Test SQL passwords against local administrator accounts.");
            Console.WriteLine("  --no-admin-reuse     Disable admin password reuse checks (default).");
            Console.WriteLine("  --show-passwords     Show raw passwords in report (dangerous).");
            Console.WriteLine("  --no-show-passwords  Redact passwords in report (default).");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  SqlServerSecurityAudit.exe");
            Console.WriteLine("    Scan all drives in standard mode, active SQL checks, no config changes.");
            Console.WriteLine();
            Console.WriteLine("  SqlServerSecurityAudit.exe --profile passive --root C:\\Projects");
            Console.WriteLine("    Scan only C:\\Projects in passive mode (no SQL connections).");
            Console.WriteLine();
            Console.WriteLine("  SqlServerSecurityAudit.exe --profile deep --output audit.txt");
            Console.WriteLine("    Deep SQL audit with xp_cmdshell/OLE toggle and admin reuse checks.");
        }
    }
}
