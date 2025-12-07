using SqlServerSecurityAudit.Core.Models;

namespace SqlServerSecurityAudit.Sql
{
    public interface ISqlProbe
    {
        ConnectionCheckResult Probe(ConnectionInfo connection, SqlProbeOptions options);
    }
}