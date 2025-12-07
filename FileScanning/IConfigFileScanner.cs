using System.Collections.Generic;

namespace SqlServerSecurityAudit.FileScanning
{
    public interface IConfigFileScanner
    {
        /// <summary>
        /// Enumerates configuration files starting from the given root directories.
        /// </summary>
        IEnumerable<string> EnumerateConfigFiles(IEnumerable<string> rootDirectories);
    }
}