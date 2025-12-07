using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using SqlServerSecurityAudit.Core.Models;

namespace SqlServerSecurityAudit.Sql
{
    public class CredentialGrouper : ICredentialGrouper
    {
        public IList<CredentialGroup> GroupByCredentials(IEnumerable<ConnectionCheckResult> results)
        {
            var groups = new Dictionary<string, CredentialGroup>(StringComparer.OrdinalIgnoreCase);

            if (results == null)
                return new List<CredentialGroup>();

            foreach (var res in results)
            {
                if (res == null || !res.ConnectionSuccess || res.Connection == null)
                    continue;

                if (string.IsNullOrWhiteSpace(res.Connection.ConnectionString))
                    continue;

                if (!TryBuildCredentialKey(res,
                        out var key,
                        out var serverDataSource,
                        out var loginDisplay,
                        out var passwordRaw,
                        out var passwordDisplay,
                        out var isWindowsAuth))
                {
                    // Fallback: group under a synthetic key so that we do not lose the result completely
                    key = "unknown|" + (res.ServerDataSource ?? "<unknown>");
                    serverDataSource = res.ServerDataSource ?? "<unknown>";
                    loginDisplay = "<unknown>";
                    passwordRaw = null;
                    passwordDisplay = "<unknown>";
                    isWindowsAuth = false;
                }

                if (!groups.TryGetValue(key, out var group))
                {
                    group = new CredentialGroup
                    {
                        ServerDataSource = serverDataSource,
                        LoginDisplay = loginDisplay,
                        PasswordRaw = passwordRaw,
                        PasswordDisplay = passwordDisplay,
                        IsWindowsAuth = isWindowsAuth
                    };
                    groups[key] = group;
                }

                group.Members.Add(res);

                if (res.Connection != null && !string.IsNullOrEmpty(res.Connection.FilePath))
                {
                    group.FilePaths.Add(res.Connection.FilePath);
                }
            }

            // Sort for stable output (server -> login -> passwordDisplay)
            var ordered = groups.Values
                .OrderBy(g => g.ServerDataSource, StringComparer.OrdinalIgnoreCase)
                .ThenBy(g => g.LoginDisplay, StringComparer.OrdinalIgnoreCase)
                .ThenBy(g => g.PasswordDisplay, StringComparer.OrdinalIgnoreCase)
                .ToList();

            return ordered;
        }

        private static bool TryBuildCredentialKey(
            ConnectionCheckResult res,
            out string key,
            out string serverDataSource,
            out string loginDisplay,
            out string passwordRaw,
            out string passwordDisplay,
            out bool isWindowsAuth)
        {
            key = null;
            serverDataSource = null;
            loginDisplay = null;
            passwordRaw = null;
            passwordDisplay = null;
            isWindowsAuth = false;

            if (res == null || res.Connection == null || string.IsNullOrWhiteSpace(res.Connection.ConnectionString))
                return false;

            try
            {
                var builder = new SqlConnectionStringBuilder(res.Connection.ConnectionString);

                serverDataSource = builder.DataSource ?? string.Empty;

                bool integrated = builder.IntegratedSecurity;
                if (!integrated)
                {
                    // Fallback check for Trusted_Connection in raw string
                    string lower = res.Connection.ConnectionString.ToLowerInvariant();
                    if (lower.Contains("trusted_connection=true") || lower.Contains("trusted_connection=yes"))
                    {
                        integrated = true;
                    }
                }

                isWindowsAuth = integrated;

                if (integrated)
                {
                    loginDisplay = "IntegratedSecurity";
                    passwordRaw = null;
                    passwordDisplay = "<windows>";
                }
                else
                {
                    loginDisplay = string.IsNullOrWhiteSpace(builder.UserID)
                        ? "<no-user>"
                        : builder.UserID.Trim();

                    string pwd = builder.Password ?? string.Empty;
                    passwordRaw = pwd;
                    passwordDisplay = string.IsNullOrEmpty(pwd) ? "<empty>" : pwd;
                }

                var sb = new StringBuilder();
                sb.Append(serverDataSource.ToLowerInvariant())
                  .Append("|")
                  .Append((loginDisplay ?? string.Empty).ToLowerInvariant())
                  .Append("|");

                if (integrated)
                {
                    sb.Append("<windows>");
                }
                else
                {
                    sb.Append(passwordRaw ?? string.Empty);
                }

                key = sb.ToString();
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
