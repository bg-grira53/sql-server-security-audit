using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.DirectoryServices.AccountManagement;
using System.Threading.Tasks;
using SqlServerSecurityAudit.Core.Models;

namespace SqlServerSecurityAudit.Security
{
    public class AdminPasswordTester : IAdminPasswordTester
    {
        // LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT
        private const int LogonTypeInteractive = 2;
        private const int LogonProviderDefault = 0;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LogonUser(
            string username,
            string domain,
            string password,
            int logonType,
            int logonProvider,
            out IntPtr token);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        // Background task that tries to build a "rich" list of admins using GetMembers(true)
        private readonly Task<List<AdminAccountInfo>> _recursiveAdminTask;

        // Final list of admin accounts to use for testing
        private List<AdminAccountInfo> _resolvedAdmins;

        private readonly object _resolveLock = new object();

        private readonly Dictionary<string, AdminPasswordCheckResult> _cache =
            new Dictionary<string, AdminPasswordCheckResult>(StringComparer.Ordinal);

        // How long we are willing to wait for the recursive enumeration when first needed
        private readonly TimeSpan _maxWaitForRecursive = TimeSpan.FromSeconds(5);

        public AdminPasswordTester()
        {
            // Start recursive enumeration in the background as early as possible.
            // It may complete successfully while the tool is scanning files / probing SQL.
            _recursiveAdminTask = Task.Run(() => EnumerateAdminsRecursive());
        }

        public AdminPasswordCheckResult Test(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                return new AdminPasswordCheckResult
                {
                    Success = false,
                    MatchedAccounts = null,
                    Error = "Password is empty."
                };
            }

            var admins = GetResolvedAdmins();

            if (admins == null || admins.Count == 0)
            {
                return new AdminPasswordCheckResult
                {
                    Success = false,
                    MatchedAccounts = null,
                    Error = "No local administrators could be enumerated."
                };
            }

            if (_cache.TryGetValue(password, out var cached))
            {
                return cached;
            }

            var successList = new List<string>();
            var lastError = new StringBuilder();

            foreach (var admin in admins)
            {
                IntPtr token = IntPtr.Zero;
                try
                {
                    bool ok = LogonUser(
                        admin.UserName,
                        admin.Domain,
                        password,
                        LogonTypeInteractive,
                        LogonProviderDefault,
                        out token);

                    if (ok)
                    {
                        successList.Add(admin.DisplayName);
                    }
                    else
                    {
                        int err = Marshal.GetLastWin32Error();
                        if (lastError.Length < 2000)
                        {
                            if (lastError.Length > 0)
                                lastError.Append(" | ");
                            lastError.AppendFormat("Logon {0} failed: {1}", admin.DisplayName, err);
                        }
                    }
                }
                catch (Exception ex)
                {
                    if (lastError.Length < 2000)
                    {
                        if (lastError.Length > 0)
                            lastError.Append(" | ");
                        lastError.AppendFormat("Exception for {0}: {1}", admin.DisplayName, ex.Message);
                    }
                }
                finally
                {
                    if (token != IntPtr.Zero)
                    {
                        try { CloseHandle(token); } catch { /* ignore */ }
                    }
                }
            }

            var result = new AdminPasswordCheckResult
            {
                Success = successList.Count > 0,
                MatchedAccounts = successList.Count > 0
                    ? string.Join("; ", successList)
                    : null,
                Error = successList.Count > 0
                    ? null
                    : (lastError.Length == 0
                        ? "No admin accounts accepted this password."
                        : lastError.ToString())
            };

            _cache[password] = result;
            return result;
        }

        /// <summary>
        /// Resolves the list of admins to use for password testing.
        /// Tries to reuse the background recursive enumeration,
        /// but falls back to a non-recursive version if it does not complete in time.
        /// </summary>
        private List<AdminAccountInfo> GetResolvedAdmins()
        {
            if (_resolvedAdmins != null)
                return _resolvedAdmins;

            lock (_resolveLock)
            {
                if (_resolvedAdmins != null)
                    return _resolvedAdmins;

                // Try to use the background recursive enumeration first
                try
                {
                    if (_recursiveAdminTask != null)
                    {
                        // Wait with timeout for recursive enumeration to complete
                        if (_recursiveAdminTask.Wait(_maxWaitForRecursive))
                        {
                            if (_recursiveAdminTask.Status == TaskStatus.RanToCompletion &&
                                _recursiveAdminTask.Result != null &&
                                _recursiveAdminTask.Result.Count > 0)
                            {
                                _resolvedAdmins = _recursiveAdminTask.Result;
                                EnsureBuiltinAdministrator(_resolvedAdmins);
                                return _resolvedAdmins;
                            }
                        }
                        // If not completed in time or faulted – fall back
                    }
                }
                catch
                {
                    // Ignore errors from background task and fall back
                }

                // Fallback: non-recursive enumeration (no nested domain groups)
                _resolvedAdmins = EnumerateAdminsNonRecursive();
                EnsureBuiltinAdministrator(_resolvedAdmins);
                return _resolvedAdmins;
            }
        }

        /// <summary>
        /// Tries to enumerate all members of the local Administrators group,
        /// expanding nested groups (GetMembers(true)).
        /// This may hang or be slow in some environments.
        /// </summary>
        private static List<AdminAccountInfo> EnumerateAdminsRecursive()
        {
            var result = new List<AdminAccountInfo>();

            try
            {
                using (var ctx = new PrincipalContext(ContextType.Machine))
                using (var group = GroupPrincipal.FindByIdentity(ctx, "Administrators"))
                {
                    if (group == null)
                        return result;

                    foreach (var m in group.GetMembers(true)) // recursive
                    {
                        try
                        {
                            string sam = m.SamAccountName;
                            if (string.IsNullOrWhiteSpace(sam))
                                continue;

                            string domain;
                            if (m.Context != null && !string.IsNullOrWhiteSpace(m.Context.Name))
                            {
                                domain = m.Context.Name;
                            }
                            else
                            {
                                domain = Environment.MachineName;
                            }

                            string display = string.Format("{0}\\{1}", domain, sam);

                            if (!result.Any(a =>
                                    a.UserName.Equals(sam, StringComparison.OrdinalIgnoreCase) &&
                                    a.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase)))
                            {
                                result.Add(new AdminAccountInfo
                                {
                                    Domain = domain,
                                    UserName = sam,
                                    DisplayName = display
                                });
                            }
                        }
                        catch
                        {
                            // Skip per-member errors
                        }
                    }
                }
            }
            catch
            {
                // Any errors here will be handled by fallback in GetResolvedAdmins
            }

            return result;
        }

        /// <summary>
        /// Fast and safe enumeration: direct members of local Administrators only.
        /// No recursive expansion of domain groups.
        /// </summary>
        private static List<AdminAccountInfo> EnumerateAdminsNonRecursive()
        {
            var result = new List<AdminAccountInfo>();

            try
            {
                using (var ctx = new PrincipalContext(ContextType.Machine))
                using (var group = GroupPrincipal.FindByIdentity(ctx, "Administrators"))
                {
                    if (group == null)
                        return result;

                    foreach (var m in group.GetMembers(false)) // non-recursive
                    {
                        try
                        {
                            string sam = m.SamAccountName;
                            if (string.IsNullOrWhiteSpace(sam))
                                continue;

                            string domain;
                            if (m.Context != null && !string.IsNullOrWhiteSpace(m.Context.Name))
                            {
                                domain = m.Context.Name;
                            }
                            else
                            {
                                domain = Environment.MachineName;
                            }

                            string display = string.Format("{0}\\{1}", domain, sam);

                            if (!result.Any(a =>
                                    a.UserName.Equals(sam, StringComparison.OrdinalIgnoreCase) &&
                                    a.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase)))
                            {
                                result.Add(new AdminAccountInfo
                                {
                                    Domain = domain,
                                    UserName = sam,
                                    DisplayName = display
                                });
                            }
                        }
                        catch
                        {
                            // Skip per-member errors
                        }
                    }
                }
            }
            catch
            {
                // If this also fails, we will at least have .\Administrator from EnsureBuiltinAdministrator
            }

            return result;
        }

        private static void EnsureBuiltinAdministrator(List<AdminAccountInfo> result)
        {
            if (result == null)
                return;

            try
            {
                string machine = Environment.MachineName;
                bool hasAdministrator = result.Any(a =>
                    a.UserName.Equals("Administrator", StringComparison.OrdinalIgnoreCase) &&
                    (a.Domain.Equals(".", StringComparison.OrdinalIgnoreCase) ||
                     a.Domain.Equals(machine, StringComparison.OrdinalIgnoreCase)));

                if (!hasAdministrator)
                {
                    result.Add(new AdminAccountInfo
                    {
                        Domain = ".",
                        UserName = "Administrator",
                        DisplayName = ".\\Administrator"
                    });
                }
            }
            catch
            {
            }
        }
    }
}
