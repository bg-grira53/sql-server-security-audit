using System;
using System.Collections.Generic;
using SqlServerSecurityAudit.Core.Models;

namespace SqlServerSecurityAudit.Reporting
{
    public class AuditReportInput
    {
        /// <summary>
        /// When the audit was executed.
        /// </summary>
        public DateTime Timestamp { get; set; }

        /// <summary>
        /// Human-readable description of root scope (e.g. "C:\" or "C:\, D:\").
        /// </summary>
        public string RootDescription { get; set; }

        /// <summary>
        /// Credential groups built from successful SQL connections.
        /// </summary>
        public IList<CredentialGroup> CredentialGroups { get; set; } =
            new List<CredentialGroup>();

        /// <summary>
        /// All password-like attributes discovered in configuration files.
        /// </summary>
        public List<PasswordCandidate> PasswordCandidates { get; set; } =
            new List<PasswordCandidate>();
    }
}