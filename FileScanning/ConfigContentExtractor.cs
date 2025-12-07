using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using SqlServerSecurityAudit.Core.Models;

namespace SqlServerSecurityAudit.FileScanning
{
    public class ConfigContentExtractor : IConfigContentExtractor
    {
        // Tokens used to detect SQL Server-like connection strings
        private static readonly string[] SqlServerServerTokens = new[]
        {
            "server=",
            "data source=",
            "addr=",
            "address=",
            "network address="
        };

        private static readonly string[] SqlServerDatabaseTokens = new[]
        {
            "initial catalog=",
            "database="
        };

        private static readonly string[] SqlServerAuthTokens = new[]
        {
            "user id=",
            "uid=",
            "trusted_connection=",
            "integrated security="
        };

        // Regex to detect "password-like" attributes
        private static readonly Regex PasswordAttributeRegex = new Regex(
            @"(?ix)['""]?(?<name>[A-Za-z0-9_\-\.]*(?:passw|pwd|psw|passwd|secret|secr|token|tok|apikey|api_key|api-key|auth|authorization|bearer)[A-Za-z0-9_\-\.]*)['""]?\s*[:=]\s*(['""])(?<value>.*?)\1",
            RegexOptions.Compiled);

        public ConfigFileAnalysis Extract(string filePath)
        {
            var analysis = new ConfigFileAnalysis();

            var text = ReadAllTextSafe(filePath);
            if (string.IsNullOrEmpty(text))
                return analysis;

            ExtractConnectionsFromText(filePath, text, analysis.Connections);
            ExtractPasswordCandidatesFromText(filePath, text, analysis.PasswordCandidates);

            return analysis;
        }

        // ===== Connection strings =====

        private void ExtractConnectionsFromText(
            string filePath,
            string text,
            List<ConnectionInfo> target)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            string[] primaryMarkers = BuildPrimaryMarkers();

            foreach (var marker in primaryMarkers)
            {
                int index = 0;
                while (true)
                {
                    index = text.IndexOf(marker, index, StringComparison.OrdinalIgnoreCase);
                    if (index == -1)
                        break;

                    int startQuoteIndex = FindStartQuote(text, index);
                    if (startQuoteIndex == -1)
                    {
                        index += marker.Length;
                        continue;
                    }

                    int endQuoteIndex = FindEndQuote(text, startQuoteIndex);
                    if (endQuoteIndex == -1)
                    {
                        index += marker.Length;
                        continue;
                    }

                    int valueStart = startQuoteIndex + 1;
                    int valueLength = endQuoteIndex - valueStart;
                    if (valueLength <= 0)
                    {
                        index = endQuoteIndex + 1;
                        continue;
                    }

                    string connStr = text.Substring(valueStart, valueLength).Trim();
                    if (string.IsNullOrEmpty(connStr) || !connStr.Contains("="))
                    {
                        index = endQuoteIndex + 1;
                        continue;
                    }

                    string snippet = ExtractLineSnippet(text, startQuoteIndex, endQuoteIndex);

                    if (!IsLikelySqlServerConnectionString(connStr, snippet))
                    {
                        index = endQuoteIndex + 1;
                        continue;
                    }

                    string key = connStr;
                    if (seen.Add(key))
                    {
                        target.Add(new ConnectionInfo
                        {
                            FilePath = filePath,
                            ConnectionString = connStr,
                            SourceSnippet = snippet
                        });
                    }

                    index = endQuoteIndex + 1;
                }
            }
        }

        // ===== Password candidates =====

        private void ExtractPasswordCandidatesFromText(
            string filePath,
            string text,
            List<PasswordCandidate> target)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (Match m in PasswordAttributeRegex.Matches(text))
            {
                if (!m.Success)
                    continue;

                string name = m.Groups["name"].Value;
                string value = m.Groups["value"].Value;

                if (string.IsNullOrWhiteSpace(value))
                    continue;

                string key = name + "|" + value;
                if (!seen.Add(key))
                    continue;

                int spanStart = m.Index;
                int spanEnd = m.Index + m.Length;

                string snippet = ExtractLineSnippet(text, spanStart, spanEnd);

                target.Add(new PasswordCandidate
                {
                    FilePath = filePath,
                    AttributeName = name,
                    PasswordValue = value,
                    SourceSnippet = snippet
                });
            }
        }

        // ===== Helper methods =====

        private static string ReadAllTextSafe(string filePath)
        {
            try
            {
                return File.ReadAllText(filePath, Encoding.UTF8);
            }
            catch
            {
                try
                {
                    return File.ReadAllText(filePath);
                }
                catch
                {
                    return null;
                }
            }
        }

        private static string[] BuildPrimaryMarkers()
        {
            var list = new List<string>();
            list.AddRange(SqlServerServerTokens);
            list.AddRange(SqlServerDatabaseTokens);
            list.AddRange(SqlServerAuthTokens);

            var set = new HashSet<string>(list, StringComparer.OrdinalIgnoreCase);
            var result = new string[set.Count];
            set.CopyTo(result);
            return result;
        }

        private static int FindStartQuote(string text, int markerIndex)
        {
            int minIndex = Math.Max(0, markerIndex - 400);
            for (int i = markerIndex - 1; i >= minIndex; i--)
            {
                char c = text[i];
                if (c == '"' || c == '\'')
                {
                    return i;
                }

                if (c == '\r' || c == '\n')
                {
                    break;
                }
            }

            return -1;
        }

        private static int FindEndQuote(string text, int startQuoteIndex)
        {
            char quote = text[startQuoteIndex];
            int maxIndex = Math.Min(text.Length - 1, startQuoteIndex + 2000);

            for (int i = startQuoteIndex + 1; i <= maxIndex; i++)
            {
                char c = text[i];
                if (c == quote)
                {
                    return i;
                }
            }

            return -1;
        }

        private static string ExtractLineSnippet(string text, int startIndex, int endIndex)
        {
            int lineStart = startIndex;
            while (lineStart > 0)
            {
                char c = text[lineStart - 1];
                if (c == '\r' || c == '\n')
                    break;
                lineStart--;
            }

            int lineEnd = endIndex;
            while (lineEnd < text.Length)
            {
                char c = text[lineEnd];
                if (c == '\r' || c == '\n')
                    break;
                lineEnd++;
            }

            string line = text.Substring(lineStart, lineEnd - lineStart).Trim();
            if (line.Length > 200)
            {
                line = line.Substring(0, 200);
            }

            return line;
        }

        private static bool IsLikelySqlServerConnectionString(string connStr, string context)
        {
            if (string.IsNullOrEmpty(connStr))
                return false;

            string lower = connStr.ToLowerInvariant();
            string contextLower = context == null ? string.Empty : context.ToLowerInvariant();

            if (contextLower.Contains("system.data.sqlclient") || contextLower.Contains("sqlclient"))
            {
                return true;
            }

            bool hasServer = ContainsAny(lower, SqlServerServerTokens);
            if (!hasServer)
            {
                return false;
            }

            bool hasDatabase = ContainsAny(lower, SqlServerDatabaseTokens);
            bool hasAuth = ContainsAny(lower, SqlServerAuthTokens);

            return hasDatabase || hasAuth;
        }

        private static bool ContainsAny(string text, IEnumerable<string> tokens)
        {
            foreach (var t in tokens)
            {
                if (text.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return false;
        }
    }
}
