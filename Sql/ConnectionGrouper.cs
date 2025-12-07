using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using SqlServerSecurityAudit.Core.Environment;
using SqlServerSecurityAudit.Core.Models;

namespace SqlServerSecurityAudit.Sql
{
    public class ConnectionGrouper : IConnectionGrouper
    {
        public IDictionary<string, List<ServerUserGroup>> GroupByServerAndLogin(IEnumerable<ConnectionInfo> connections)
        {
            var result = new Dictionary<string, List<ServerUserGroup>>(StringComparer.OrdinalIgnoreCase);

            if (connections == null)
                return result;

            foreach (var info in connections)
            {
                if (info == null || string.IsNullOrWhiteSpace(info.ConnectionString))
                    continue;

                if (!TryGetServerAndLogin(info.ConnectionString, out var serverKey, out var loginKey))
                {
                    // Fallback: treat this connection string as its own "server"
                    serverKey = "UnknownServer:" + info.ConnectionString.GetHashCode();
                    loginKey = "UnknownLogin";
                }

                if (!result.TryGetValue(serverKey, out var userGroups))
                {
                    userGroups = new List<ServerUserGroup>();
                    result[serverKey] = userGroups;
                }

                var group = userGroups.Find(g =>
                    string.Equals(g.LoginKey, loginKey, StringComparison.OrdinalIgnoreCase));

                if (group == null)
                {
                    group = new ServerUserGroup
                    {
                        ServerKey = serverKey,
                        LoginKey = loginKey
                    };
                    userGroups.Add(group);
                }

                group.Connections.Add(info);
            }

            return result;
        }

        private static bool TryGetServerAndLogin(string connectionString, out string serverKey, out string loginKey)
        {
            serverKey = null;
            loginKey = null;

            if (string.IsNullOrWhiteSpace(connectionString))
                return false;

            try
            {
                var builder = new SqlConnectionStringBuilder(connectionString);

                string dataSource = builder.DataSource;
                if (string.IsNullOrWhiteSpace(dataSource))
                    return false;

                HostUtils.SplitDataSourceForNormalization(dataSource, out var prefix, out var host, out var suffix);

                string normalizedHost = HostUtils.NormalizeHostForGrouping(host);
                if (string.IsNullOrWhiteSpace(normalizedHost))
                    normalizedHost = host;

                string normalizedDataSource = (prefix ?? string.Empty) +
                                              (normalizedHost ?? string.Empty) +
                                              (suffix ?? string.Empty);

                serverKey = normalizedDataSource.Trim();

                if (builder.IntegratedSecurity)
                {
                    loginKey = "IntegratedSecurity";
                }
                else if (!string.IsNullOrWhiteSpace(builder.UserID))
                {
                    loginKey = builder.UserID.Trim();
                }
                else
                {
                    loginKey = "UnknownLogin";
                }

                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
