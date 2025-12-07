using SqlServerSecurityAudit.Core.Models;

namespace SqlServerSecurityAudit.FileScanning
{
    public interface IConfigContentExtractor
    {
        /// <summary>
        /// Reads and analyzes a configuration file once and returns both
        /// connection strings and password-like attributes.
        /// </summary>
        ConfigFileAnalysis Extract(string filePath);
    }
}