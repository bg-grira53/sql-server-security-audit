using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace SqlServerSecurityAudit.Core.Environment
{
    public static class HostUtils
    {
        public static readonly string LocalHostName = GetLocalHostNameOnce();
        public static readonly string[] LocalIPv4Addresses = GetLocalIPv4AddressesOnce();

        public static readonly HashSet<string> ExcludedDirectoryNames =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Windows",
                "Program Files",
                "Program Files (x86)",
                "ProgramData",
                "System Volume Information",
                "$Recycle.Bin",
                "Recovery",
                "PerfLogs",
                "MSOCache"
            };

        private static string GetLocalHostNameOnce()
        {
            try
            {
                return Dns.GetHostName();
            }
            catch
            {
                return null;
            }
        }

        private static string[] GetLocalIPv4AddressesOnce()
        {
            try
            {
                if (string.IsNullOrEmpty(LocalHostName))
                    return Array.Empty<string>();

                return Dns.GetHostAddresses(LocalHostName)
                    .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                    .Select(a => a.ToString())
                    .ToArray();
            }
            catch
            {
                return Array.Empty<string>();
            }
        }

        public static void SplitDataSourceForNormalization(
            string dataSource,
            out string prefix,
            out string host,
            out string suffix)
        {
            prefix = string.Empty;
            host = dataSource;
            suffix = string.Empty;

            if (string.IsNullOrWhiteSpace(dataSource))
                return;

            string ds = dataSource.Trim();

            int colonIndex = ds.IndexOf(':');
            if (colonIndex == 3 || colonIndex == 4) // "np:", "tcp:", "lpc:"
            {
                prefix = ds.Substring(0, colonIndex + 1);
                ds = ds.Substring(colonIndex + 1);
            }

            int splitIndex = ds.Length;
            int commaIndex = ds.IndexOf(',');
            if (commaIndex >= 0 && commaIndex < splitIndex)
                splitIndex = commaIndex;

            int backslashIndex = ds.IndexOf('\\');
            if (backslashIndex >= 0 && backslashIndex < splitIndex)
                splitIndex = backslashIndex;

            host = ds.Substring(0, splitIndex);
            suffix = ds.Substring(splitIndex);
        }

        public static string NormalizeHostForGrouping(string host)
        {
            if (string.IsNullOrWhiteSpace(host))
                return host;

            string h = host.Trim();

            if (h == "." ||
                h.Equals("(local)", StringComparison.OrdinalIgnoreCase) ||
                h.Equals("(localdb)", StringComparison.OrdinalIgnoreCase) ||
                h.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                h == "127.0.0.1" ||
                h == "::1" ||
                (LocalIPv4Addresses != null && LocalIPv4Addresses.Contains(h)))
            {
                if (!string.IsNullOrEmpty(LocalHostName))
                    return LocalHostName;
            }

            if (!string.IsNullOrEmpty(LocalHostName) &&
                h.Equals(LocalHostName, StringComparison.OrdinalIgnoreCase))
            {
                return LocalHostName;
            }

            return h;
        }
    }
}
