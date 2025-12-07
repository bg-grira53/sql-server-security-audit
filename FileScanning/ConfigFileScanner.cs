using System;
using System.Collections.Generic;
using System.IO;
using SqlServerSecurityAudit.Core.Environment;

namespace SqlServerSecurityAudit.FileScanning
{
    public class ConfigFileScanner : IConfigFileScanner
    {
        public IEnumerable<string> EnumerateConfigFiles(IEnumerable<string> rootDirectories)
        {
            if (rootDirectories == null)
                yield break;

            var stack = new Stack<string>();

            foreach (var root in rootDirectories)
            {
                if (string.IsNullOrWhiteSpace(root))
                    continue;

                if (!Directory.Exists(root))
                    continue;

                stack.Push(root);
            }

            while (stack.Count > 0)
            {
                var currentDir = stack.Pop();

                string[] files;
                try
                {
                    files = Directory.GetFiles(currentDir);
                }
                catch
                {
                    // Access denied or other IO issues - skip this directory
                    continue;
                }

                foreach (var file in files)
                {
                    string fileName;
                    try
                    {
                        fileName = Path.GetFileName(file);
                    }
                    catch
                    {
                        continue;
                    }

                    if (string.IsNullOrEmpty(fileName))
                        continue;

                    var lowerName = fileName.ToLowerInvariant();

                    bool isTargetConfig =
                           lowerName == "web.config"
                        || lowerName == "app.config"
                        || lowerName == "connectionstrings.config"
                        || lowerName == "appsettings.json"
                        || (lowerName.StartsWith("appsettings.", StringComparison.OrdinalIgnoreCase)
                            && lowerName.EndsWith(".json", StringComparison.OrdinalIgnoreCase));

                    if (isTargetConfig)
                    {
                        yield return file;
                    }
                }

                string[] subdirs;
                try
                {
                    subdirs = Directory.GetDirectories(currentDir);
                }
                catch
                {
                    // Access denied or other IO issues - skip subdirectories
                    continue;
                }

                foreach (var dir in subdirs)
                {
                    try
                    {
                        var trimmed = dir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                        string dirName = Path.GetFileName(trimmed);

                        if (!string.IsNullOrEmpty(dirName) &&
                            HostUtils.ExcludedDirectoryNames.Contains(dirName))
                        {
                            // Skip heavy/system directories
                            continue;
                        }
                    }
                    catch
                    {
                        // If we cannot get the directory name, still try to traverse it
                    }

                    stack.Push(dir);
                }
            }
        }
    }
}
