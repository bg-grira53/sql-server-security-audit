using System.Collections.Generic;
using SqlServerSecurityAudit.Core.Models;

namespace SqlServerSecurityAudit.Sql
{
    public interface ICredentialGrouper
    {
        /// <summary>
        /// Groups successful connection check results by (server, login, password).
        /// </summary>
        IList<CredentialGroup> GroupByCredentials(IEnumerable<ConnectionCheckResult> results);
    }
}