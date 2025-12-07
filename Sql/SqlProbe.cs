using System;
using System.Data.SqlClient;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.DirectoryServices.AccountManagement;
using SqlServerSecurityAudit.Core.Environment;
using SqlServerSecurityAudit.Core.Models;

namespace SqlServerSecurityAudit.Sql
{
    public class SqlProbe : ISqlProbe
    {
        private sealed class SqlSurfaceConfiguration
        {
            public int? ShowAdvancedOptions { get; set; }
            public int? XpCmdShell { get; set; }
            public int? OleAutomationProcedures { get; set; }
            public int? ExternalScriptsEnabled { get; set; }
        }

        public ConnectionCheckResult Probe(ConnectionInfo connection, SqlProbeOptions options)
        {
            if (connection == null)
                throw new ArgumentNullException(nameof(connection));

            if (options == null)
                throw new ArgumentNullException(nameof(options));

            var result = new ConnectionCheckResult
            {
                Connection = connection
            };

            if (!options.EnableActiveChecks)
            {
                result.ErrorMessage = "Active SQL checks are disabled by options.";
                return result;
            }

            SqlConnection conn = null;
            var errorBuilder = new StringBuilder();

            string serverDataSource = null;
            string serverIpAddress = null;
            bool? isLocalServer = null;

            try
            {
                // Basic server info from connection string
                TryPopulateServerInfo(connection.ConnectionString, out serverDataSource, out serverIpAddress, out isLocalServer);

                conn = new SqlConnection(connection.ConnectionString);
                conn.Open();
                result.ConnectionSuccess = true;
                result.SuccessfulConnectionString = connection.ConnectionString;

                // Who are we inside SQL Server
                PopulateSqlIdentity(conn, result, errorBuilder);

                // Service account and domain admin check
                CheckSqlServiceAccount(conn, result, errorBuilder);

                // Surface configuration (xp_cmdshell, Ole Automation, external scripts)
                var surface = ReadSurfaceConfiguration(conn, errorBuilder);

                // Set external scripts flag from configuration (we do not toggle it)
                result.ExternalScriptsEnabled =
                    surface.ExternalScriptsEnabled.HasValue &&
                    surface.ExternalScriptsEnabled.Value == 1;

                // Command execution probes (xp_cmdshell, Ole Automation, external scripts)
                RunCommandExecutionProbes(conn, result, surface, options, errorBuilder);

                // SQL Agent CmdExec surface
                CheckSqlAgentSurface(conn, result, errorBuilder);

                // Linked servers with RPC OUT
                CheckLinkedServersRpcOut(conn, result, errorBuilder);

                string err = errorBuilder.ToString().Trim();
                if (err.EndsWith("|"))
                {
                    err = err.TrimEnd(' ', '|');
                }

                result.ErrorMessage = string.IsNullOrEmpty(err) ? null : err;
            }
            catch (Exception ex)
            {
                result.ConnectionSuccess = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                conn?.Dispose();
            }

            result.ServerDataSource = serverDataSource;
            result.ServerIpAddress = serverIpAddress;
            result.IsLocalServer = isLocalServer;

            return result;
        }

        // ===== Basic server info =====

        private static void TryPopulateServerInfo(
            string connectionString,
            out string dataSource,
            out string ipAddress,
            out bool? isLocal)
        {
            dataSource = null;
            ipAddress = null;
            isLocal = null;

            try
            {
                var builder = new SqlConnectionStringBuilder(connectionString);
                dataSource = builder.DataSource;

                string host = ExtractHostFromDataSource(dataSource);
                ipAddress = ResolveServerIp(host);
                isLocal = DetermineIsLocalServer(host, ipAddress);
            }
            catch
            {
                // Best-effort only
            }
        }

        private static void PopulateSqlIdentity(SqlConnection conn, ConnectionCheckResult result, StringBuilder errorBuilder)
        {
            if (conn == null) throw new ArgumentNullException(nameof(conn));
            if (result == null) throw new ArgumentNullException(nameof(result));

            try
            {
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = "SELECT SYSTEM_USER, ORIGINAL_LOGIN();";
                    cmd.CommandTimeout = 10;

                    using (var reader = cmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            if (!reader.IsDBNull(0))
                            {
                                result.ActualSystemUser = reader.GetString(0);
                            }

                            if (!reader.IsDBNull(1))
                            {
                                result.ActualOriginalLogin = reader.GetString(1);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                errorBuilder.Append("SYSTEM_USER / ORIGINAL_LOGIN check failed: ")
                    .Append(ex.Message)
                    .Append(" | ");
            }
        }

        private static string ExtractHostFromDataSource(string dataSource)
        {
            if (string.IsNullOrWhiteSpace(dataSource))
                return null;

            string ds = dataSource.Trim();

            int colonIndex = ds.IndexOf(':');
            if (colonIndex == 3 || colonIndex == 4) // "np:", "tcp:", "lpc:"
            {
                ds = ds.Substring(colonIndex + 1);
            }

            int commaIndex = ds.IndexOf(',');
            if (commaIndex > 0)
            {
                ds = ds.Substring(0, commaIndex);
            }

            int backslashIndex = ds.IndexOf('\\');
            if (backslashIndex > 0)
            {
                ds = ds.Substring(0, backslashIndex);
            }

            return ds.Trim();
        }

        private static string ResolveServerIp(string host)
        {
            if (string.IsNullOrWhiteSpace(host))
                return null;

            try
            {
                string hostForDns = host;

                if (host == "." || host.Equals("(local)", StringComparison.OrdinalIgnoreCase))
                {
                    hostForDns = HostUtils.LocalHostName ?? host;
                }

                if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
                {
                    hostForDns = "localhost";
                }

                var addresses = Dns.GetHostAddresses(hostForDns);
                var ipv4 = Array.Find(addresses, a => a.AddressFamily == AddressFamily.InterNetwork);
                if (ipv4 != null)
                {
                    return ipv4.ToString();
                }

                var any = addresses.Length > 0 ? addresses[0] : null;
                return any?.ToString();
            }
            catch
            {
                return null;
            }
        }

        private static bool? DetermineIsLocalServer(string host, string ip)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(host) && string.IsNullOrWhiteSpace(ip))
                    return null;

                if (host == "." ||
                    host.Equals("(local)", StringComparison.OrdinalIgnoreCase) ||
                    host.Equals("(localdb)", StringComparison.OrdinalIgnoreCase) ||
                    host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                if (!string.IsNullOrEmpty(HostUtils.LocalHostName) &&
                    !string.IsNullOrEmpty(host) &&
                    host.Equals(HostUtils.LocalHostName, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                if (!string.IsNullOrEmpty(ip))
                {
                    if (ip == "127.0.0.1" || ip == "::1")
                        return true;

                    if (HostUtils.LocalIPv4Addresses != null &&
                        HostUtils.LocalIPv4Addresses.Length > 0 &&
                        Array.IndexOf(HostUtils.LocalIPv4Addresses, ip) >= 0)
                    {
                        return true;
                    }

                    return false;
                }

                return null;
            }
            catch
            {
                return null;
            }
        }

        // ===== Surface configuration (xp_cmdshell, Ole Automation, external scripts) =====

        private static SqlSurfaceConfiguration ReadSurfaceConfiguration(SqlConnection conn, StringBuilder errorBuilder)
        {
            var cfg = new SqlSurfaceConfiguration();

            try
            {
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText =
                        "SELECT name, value_in_use " +
                        "FROM sys.configurations " +
                        "WHERE name IN ('xp_cmdshell', 'show advanced options', 'Ole Automation Procedures', 'external scripts enabled');";
                    cmd.CommandTimeout = 15;

                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            string name = reader.GetString(0);
                            int value = Convert.ToInt32(reader["value_in_use"]);

                            if (string.Equals(name, "xp_cmdshell", StringComparison.OrdinalIgnoreCase))
                            {
                                cfg.XpCmdShell = value;
                            }
                            else if (string.Equals(name, "show advanced options", StringComparison.OrdinalIgnoreCase))
                            {
                                cfg.ShowAdvancedOptions = value;
                            }
                            else if (string.Equals(name, "Ole Automation Procedures", StringComparison.OrdinalIgnoreCase))
                            {
                                cfg.OleAutomationProcedures = value;
                            }
                            else if (string.Equals(name, "external scripts enabled", StringComparison.OrdinalIgnoreCase))
                            {
                                cfg.ExternalScriptsEnabled = value;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                errorBuilder.Append("Read sys.configurations failed: ")
                    .Append(ex.Message)
                    .Append(" | ");
            }

            return cfg;
        }

        private static void RunCommandExecutionProbes(
            SqlConnection conn,
            ConnectionCheckResult result,
            SqlSurfaceConfiguration cfg,
            SqlProbeOptions options,
            StringBuilder errorBuilder)
        {
            bool showAdvancedChanged = false;
            bool xpCmdShellChanged = false;
            bool oleAutomationChanged = false;

            // Enable advanced options / xp_cmdshell / Ole Automation if allowed by options
            try
            {
                using (var cmd = conn.CreateCommand())
                {
                    var sb = new StringBuilder();

                    bool needAdvancedForXp = options.AllowXpCmdShellToggle &&
                                             (!cfg.XpCmdShell.HasValue || cfg.XpCmdShell.Value == 0);
                    bool needAdvancedForOle = options.AllowOleAutomationToggle &&
                                              (!cfg.OleAutomationProcedures.HasValue || cfg.OleAutomationProcedures.Value == 0);

                    if (!cfg.ShowAdvancedOptions.HasValue || cfg.ShowAdvancedOptions.Value == 0)
                    {
                        if (needAdvancedForXp || needAdvancedForOle)
                        {
                            sb.Append("EXEC sp_configure 'show advanced options', 1; ")
                              .Append("RECONFIGURE; ");
                            showAdvancedChanged = true;
                        }
                    }

                    if (options.AllowXpCmdShellToggle &&
                        (!cfg.XpCmdShell.HasValue || cfg.XpCmdShell.Value == 0))
                    {
                        sb.Append("EXEC sp_configure 'xp_cmdshell', 1; ")
                          .Append("RECONFIGURE; ");
                        xpCmdShellChanged = true;
                    }

                    if (options.AllowOleAutomationToggle &&
                        (!cfg.OleAutomationProcedures.HasValue || cfg.OleAutomationProcedures.Value == 0))
                    {
                        sb.Append("EXEC sp_configure 'Ole Automation Procedures', 1; ")
                          .Append("RECONFIGURE; ");
                        oleAutomationChanged = true;
                    }

                    cmd.CommandText = sb.ToString();
                    cmd.CommandTimeout = 30;

                    if (!string.IsNullOrWhiteSpace(cmd.CommandText))
                    {
                        cmd.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception ex)
            {
                errorBuilder.Append("Enable xp_cmdshell / Ole Automation failed: ")
                    .Append(ex.Message)
                    .Append(" | ");
            }

            bool xpCmdShellUsable =
                (cfg.XpCmdShell.HasValue && cfg.XpCmdShell.Value == 1) || xpCmdShellChanged;

            bool oleAutomationUsable =
                (cfg.OleAutomationProcedures.HasValue && cfg.OleAutomationProcedures.Value == 1) || oleAutomationChanged;

            // xp_cmdshell whoami
            if (xpCmdShellUsable)
            {
                RunXpCmdShellWhoAmI(conn, result, errorBuilder);
            }
            else
            {
                result.XpCmdShellSuccess = false;
            }

            // OLE Automation whoami
            if (oleAutomationUsable)
            {
                result.OleAutomationTried = true;
                RunOleAutomationWhoAmI(conn, result, errorBuilder);
            }
            else
            {
                result.OleAutomationTried = false;
            }

            // External scripts (R / Python) whoami
            if (result.ExternalScriptsEnabled)
            {
                RunExternalScriptsWhoAmI(conn, result, errorBuilder);
            }

            // Restore configuration if we changed something
            try
            {
                using (var cmd = conn.CreateCommand())
                {
                    var sb = new StringBuilder();

                    if (xpCmdShellChanged && cfg.XpCmdShell.HasValue && cfg.XpCmdShell.Value == 0)
                    {
                        sb.Append("EXEC sp_configure 'xp_cmdshell', 0; ")
                          .Append("RECONFIGURE; ");
                    }

                    if (oleAutomationChanged && cfg.OleAutomationProcedures.HasValue && cfg.OleAutomationProcedures.Value == 0)
                    {
                        sb.Append("EXEC sp_configure 'Ole Automation Procedures', 0; ")
                          .Append("RECONFIGURE; ");
                    }

                    if (showAdvancedChanged && cfg.ShowAdvancedOptions.HasValue && cfg.ShowAdvancedOptions.Value == 0)
                    {
                        sb.Append("EXEC sp_configure 'show advanced options', 0; ")
                          .Append("RECONFIGURE; ");
                    }

                    cmd.CommandText = sb.ToString();
                    cmd.CommandTimeout = 30;

                    if (!string.IsNullOrWhiteSpace(cmd.CommandText))
                    {
                        cmd.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception ex)
            {
                errorBuilder.Append("Restore configuration failed: ")
                    .Append(ex.Message)
                    .Append(" | ");
            }
        }

        private static void RunXpCmdShellWhoAmI(SqlConnection conn, ConnectionCheckResult result, StringBuilder errorBuilder)
        {
            try
            {
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = "EXEC master..xp_cmdshell 'whoami';";
                    cmd.CommandTimeout = 30;

                    using (var reader = cmd.ExecuteReader())
                    {
                        var sb = new StringBuilder();
                        while (reader.Read())
                        {
                            if (!reader.IsDBNull(0))
                            {
                                string line = reader.GetString(0);
                                if (!string.IsNullOrWhiteSpace(line))
                                {
                                    if (sb.Length > 0)
                                    {
                                        sb.Append(" | ");
                                    }
                                    sb.Append(line.Trim());
                                }
                            }
                        }

                        if (sb.Length > 0)
                        {
                            result.XpCmdShellSuccess = true;
                            result.XpCmdShellWhoAmI = sb.ToString();
                        }
                        else
                        {
                            result.XpCmdShellSuccess = false;
                            errorBuilder.Append("xp_cmdshell returned no rows. | ");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                result.XpCmdShellSuccess = false;
                errorBuilder.Append("xp_cmdshell whoami failed: ")
                    .Append(ex.Message)
                    .Append(" | ");
            }
        }

        private static void RunOleAutomationWhoAmI(SqlConnection conn, ConnectionCheckResult result, StringBuilder errorBuilder)
        {
            try
            {
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = @"
DECLARE @hr INT, @shell INT, @exec INT, @output NVARCHAR(4000);

EXEC @hr = sp_OACreate 'WScript.Shell', @shell OUT;
IF @hr <> 0
BEGIN
    SELECT CAST(NULL AS NVARCHAR(4000)) AS whoami_output;
    RETURN;
END;

EXEC @hr = sp_OAMethod @shell, 'Exec', @exec OUT, 'cmd /c whoami';
IF @hr <> 0
BEGIN
    SELECT CAST(NULL AS NVARCHAR(4000)) AS whoami_output;
    RETURN;
END;

EXEC @hr = sp_OAGetProperty @exec, 'StdOut.ReadAll', @output OUT;
IF @hr <> 0
BEGIN
    SELECT CAST(NULL AS NVARCHAR(4000)) AS whoami_output;
    RETURN;
END;

SELECT @output AS whoami_output;
";
                    cmd.CommandTimeout = 30;

                    using (var reader = cmd.ExecuteReader())
                    {
                        string output = null;
                        if (reader.Read() && !reader.IsDBNull(0))
                        {
                            output = reader.GetString(0);
                        }

                        if (!string.IsNullOrWhiteSpace(output))
                        {
                            result.OleAutomationWhoAmISuccess = true;
                            result.OleAutomationWhoAmI = output.Trim();
                        }
                        else
                        {
                            result.OleAutomationWhoAmISuccess = false;
                            errorBuilder.Append("OLE Automation whoami returned no output. | ");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                result.OleAutomationWhoAmISuccess = false;
                errorBuilder.Append("OLE Automation whoami failed: ")
                    .Append(ex.Message)
                    .Append(" | ");
            }
        }

        private static void RunExternalScriptsWhoAmI(SqlConnection conn, ConnectionCheckResult result, StringBuilder errorBuilder)
        {
            bool externalSuccess = false;
            string externalLang = null;
            string externalOutput = null;

            // Try R first
            try
            {
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = @"
EXEC sp_execute_external_script
    @language = N'R',
    @script   = N'OutputDataSet <- data.frame(whoami = system(""whoami"", intern = TRUE));';
";
                    cmd.CommandTimeout = 60;

                    using (var reader = cmd.ExecuteReader())
                    {
                        string output = null;
                        if (reader.Read() && !reader.IsDBNull(0))
                        {
                            output = reader.GetString(0);
                        }

                        if (!string.IsNullOrWhiteSpace(output))
                        {
                            externalSuccess = true;
                            externalLang = "R";
                            externalOutput = output.Trim();
                        }
                    }
                }
            }
            catch (Exception exR)
            {
                errorBuilder.Append("External scripts R whoami failed: ")
                    .Append(exR.Message)
                    .Append(" | ");
            }

            // If R did not work, try Python
            if (!externalSuccess)
            {
                try
                {
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = @"
EXEC sp_execute_external_script
    @language = N'Python',
    @script   = N'import os, pandas as pd
who = os.popen(""whoami"").read().strip()
OutputDataSet = pd.DataFrame({""whoami"":[who]})';
";
                        cmd.CommandTimeout = 60;

                        using (var reader = cmd.ExecuteReader())
                        {
                            string output = null;
                            if (reader.Read() && !reader.IsDBNull(0))
                            {
                                output = reader.GetString(0);
                            }

                            if (!string.IsNullOrWhiteSpace(output))
                            {
                                externalSuccess = true;
                                externalLang = "Python";
                                externalOutput = output.Trim();
                            }
                        }
                    }
                }
                catch (Exception exPy)
                {
                    errorBuilder.Append("External scripts Python whoami failed: ")
                        .Append(exPy.Message)
                        .Append(" | ");
                }
            }

            result.ExternalScriptsWhoAmISuccess = externalSuccess;
            result.ExternalScriptsLanguage = externalLang;
            result.ExternalScriptsWhoAmI = externalOutput;
        }

        // ===== SQL Agent CmdExec surface =====

        private static void CheckSqlAgentSurface(SqlConnection conn, ConnectionCheckResult result, StringBuilder errorBuilder)
        {
            result.SqlAgentSurfaceChecked = true;

            try
            {
                int isUser = 0, isReader = 0, isOperator = 0;
                int cmdExecSteps = 0;
                string roles = "";

                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = @"
IF DB_ID('msdb') IS NOT NULL
BEGIN
    USE msdb;
    SELECT 
        IS_MEMBER('SQLAgentUserRole')     AS is_user,
        IS_MEMBER('SQLAgentReaderRole')   AS is_reader,
        IS_MEMBER('SQLAgentOperatorRole') AS is_operator;
END
ELSE
BEGIN
    SELECT 0 AS is_user, 0 AS is_reader, 0 AS is_operator;
END
";
                    cmd.CommandTimeout = 15;

                    using (var reader = cmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            isUser = reader.IsDBNull(0) ? 0 : reader.GetInt32(0);
                            isReader = reader.IsDBNull(1) ? 0 : reader.GetInt32(1);
                            isOperator = reader.IsDBNull(2) ? 0 : reader.GetInt32(2);
                        }
                    }
                }

                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = @"
IF DB_ID('msdb') IS NOT NULL
BEGIN
    SELECT COUNT(*) 
    FROM msdb.dbo.sysjobsteps 
    WHERE subsystem = 'CmdExec';
END
ELSE
BEGIN
    SELECT 0;
END
";
                    cmd.CommandTimeout = 15;
                    object scalar = cmd.ExecuteScalar();
                    if (scalar != null && scalar != DBNull.Value)
                    {
                        cmdExecSteps = Convert.ToInt32(scalar);
                    }
                }

                var rolesList = new System.Collections.Generic.List<string>();
                if (isUser == 1) rolesList.Add("SQLAgentUserRole");
                if (isReader == 1) rolesList.Add("SQLAgentReaderRole");
                if (isOperator == 1) rolesList.Add("SQLAgentOperatorRole");
                roles = rolesList.Count > 0 ? string.Join(",", rolesList) : "none";

                result.SqlAgentCmdExecJobStepCount = cmdExecSteps;
                result.SqlAgentRoles = roles;
                result.SqlAgentCmdExecSurfacePresent = (cmdExecSteps > 0 && rolesList.Count > 0);
            }
            catch (Exception ex)
            {
                errorBuilder.Append("SQL Agent surface check failed: ")
                    .Append(ex.Message)
                    .Append(" | ");
            }
        }

        // ===== Linked servers with RPC OUT =====

        private static void CheckLinkedServersRpcOut(SqlConnection conn, ConnectionCheckResult result, StringBuilder errorBuilder)
        {
            result.LinkedServersChecked = true;

            try
            {
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = @"
SELECT COUNT(*) 
FROM sys.servers 
WHERE is_linked = 1 AND is_rpc_out_enabled = 1;
";
                    cmd.CommandTimeout = 15;
                    object scalar = cmd.ExecuteScalar();
                    if (scalar != null && scalar != DBNull.Value)
                    {
                        result.LinkedServersRpcOutCount = Convert.ToInt32(scalar);
                        result.LinkedServersRpcOutPresent = (result.LinkedServersRpcOutCount > 0);
                    }
                }
            }
            catch (Exception ex)
            {
                errorBuilder.Append("Linked servers RPC OUT check failed: ")
                    .Append(ex.Message)
                    .Append(" | ");
            }
        }

        // ===== Service account & Domain Admin check =====

        private static void CheckSqlServiceAccount(SqlConnection conn, ConnectionCheckResult result, StringBuilder errorBuilder)
        {
            try
            {
                string serviceAccount = null;

                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = @"
SELECT TOP (1) service_account
FROM sys.dm_server_services
WHERE servicename = 'SQL Server' 
   OR servicename LIKE 'SQL Server (%'
ORDER BY servicename;
";
                    cmd.CommandTimeout = 10;
                    object scalar = cmd.ExecuteScalar();
                    if (scalar != null && scalar != DBNull.Value)
                    {
                        serviceAccount = Convert.ToString(scalar);
                    }
                }

                if (string.IsNullOrWhiteSpace(serviceAccount))
                {
                    result.SqlServiceAccount = null;
                    result.SqlServiceAccountIsDomainAccount = null;
                    result.SqlServiceAccountIsDomainAdmin = null;
                    result.SqlServiceAccountCheckError = "Could not determine SQL Server service account from sys.dm_server_services.";
                    return;
                }

                serviceAccount = serviceAccount.Trim();
                result.SqlServiceAccount = serviceAccount;

                if (serviceAccount.StartsWith("NT AUTHORITY\\", StringComparison.OrdinalIgnoreCase) ||
                    serviceAccount.StartsWith("NT SERVICE\\", StringComparison.OrdinalIgnoreCase) ||
                    serviceAccount.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase) ||
                    serviceAccount.Equals("Local Service", StringComparison.OrdinalIgnoreCase) ||
                    serviceAccount.Equals("Network Service", StringComparison.OrdinalIgnoreCase))
                {
                    result.SqlServiceAccountIsDomainAccount = false;
                    result.SqlServiceAccountIsDomainAdmin = false;
                    return;
                }

                if (!serviceAccount.Contains("\\"))
                {
                    result.SqlServiceAccountIsDomainAccount = false;
                    result.SqlServiceAccountIsDomainAdmin = false;
                    return;
                }

                result.SqlServiceAccountIsDomainAccount = true;

                string checkError;
                bool? isDomainAdmin = TryCheckDomainAdmin(serviceAccount, out checkError);
                result.SqlServiceAccountIsDomainAdmin = isDomainAdmin;
                result.SqlServiceAccountCheckError = checkError;

                if (!string.IsNullOrEmpty(checkError))
                {
                    errorBuilder.Append("SQL service account domain admin check: ")
                                .Append(checkError)
                                .Append(" | ");
                }
            }
            catch (Exception ex)
            {
                result.SqlServiceAccountCheckError = ex.Message;
                errorBuilder.Append("SQL service account check failed: ")
                            .Append(ex.Message)
                            .Append(" | ");
            }
        }

        private static bool? TryCheckDomainAdmin(string domainBackslashUser, out string error)
        {
            error = null;

            try
            {
                if (string.IsNullOrWhiteSpace(domainBackslashUser))
                {
                    error = "Empty service account name.";
                    return null;
                }

                var parts = domainBackslashUser.Split('\\');
                if (parts.Length != 2)
                {
                    error = "Service account is not in DOMAIN\\User format.";
                    return null;
                }

                string domain = parts[0];
                string user = parts[1];

                if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(user))
                {
                    error = "Invalid domain or user part in service account.";
                    return null;
                }

                using (var context = new PrincipalContext(ContextType.Domain, domain))
                using (var userPrincipal = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, user))
                {
                    if (userPrincipal == null)
                    {
                        error = "User not found in domain.";
                        return null;
                    }

                    using (var daGroup = GroupPrincipal.FindByIdentity(context, "Domain Admins"))
                    {
                        if (daGroup == null)
                        {
                            error = "Group 'Domain Admins' not found in domain.";
                            return null;
                        }

                        bool isMember = userPrincipal.IsMemberOf(daGroup);
                        return isMember;
                    }
                }
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return null;
            }
        }
    }
}
