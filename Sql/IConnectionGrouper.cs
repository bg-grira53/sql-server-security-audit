using System.Collections.Generic;
using SqlServerSecurityAudit.Core.Models;

namespace SqlServerSecurityAudit.Sql
{
    public interface IConnectionGrouper
    {
        /// <summary>
        /// Groups connections by normalized server key and login key.
        /// </summary>
        IDictionary<string, List<ServerUserGroup>> GroupByServerAndLogin(IEnumerable<ConnectionInfo> connections);
    }
}