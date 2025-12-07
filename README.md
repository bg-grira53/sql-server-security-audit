# Sql Server Security Audit Tool

**Author / Maintainer:** [@defsecapp](https://github.com/defsecapp)

**SqlServerSecurityAudit** is a Windows console tool that helps security engineers and developers **discover risky SQL Server access surfaces** by:

- scanning application configuration files for SQL Server connection strings and password-like attributes;
- actively connecting to SQL Server (optional) and checking command execution surfaces such as `xp_cmdshell`, OLE Automation, external scripts, SQL Agent CmdExec, and linked servers;
- detecting **password reuse** between SQL logins and **local administrator accounts**;
- producing a **text report** summarizing findings in a human-readable format.

The tool is written in C# / .NET (target: .NET Framework 4.8) and is designed as a defensive AppSec utility.

---

## Features

### File scanning

- Recursively scans directory roots (or all suitable drives, if no root is specified).
- Looks for common .NET / web configuration files:
  - `web.config`
  - `app.config`
  - `connectionStrings.config`
  - `appsettings.json`
  - `appsettings.*.json`
- Extracts:
  - **SQL Server–like connection strings** (using heuristics over `Data Source/Server`, `Initial Catalog/Database`, and auth tokens).
  - **Password-like attributes** using a regex over names such as:
    - `passw`, `pwd`, `psw`, `passwd`, `secret`, `token`, `apikey`, `auth`, `authorization`, `bearer`, etc.

### Connection string grouping & active SQL checks

- Groups connection strings by **(server, login)** to reduce the number of SQL connections.
- For each distinct (server, login) pair (if active checks are enabled), the tool:
  - connects to SQL Server using `SqlConnection`;
  - records `SYSTEM_USER` and `ORIGINAL_LOGIN()` for effective identity;
  - collects **server info**:
    - data source, resolved IP address,
    - whether the server appears local or remote (based on host/IP comparison).

### Command execution surfaces in SQL Server

For each successful connection, the tool checks a set of potential **command execution surfaces**:

- **Configuration flags** from `sys.configurations`:
  - `xp_cmdshell`
  - `show advanced options`
  - `Ole Automation Procedures`
  - `external scripts enabled`
- **`xp_cmdshell`**:
  - optionally enables it via `sp_configure` (when allowed in options);
  - runs `EXEC master..xp_cmdshell 'whoami';`
  - records success and captured output.
- **OLE Automation Procedures** (`sp_OACreate` / `WScript.Shell`):
  - optionally enables it via `sp_configure` (when allowed in options);
  - runs `whoami` through `cmd /c whoami` using `WScript.Shell`;
  - records output if successful.
- **External scripts** (`sp_execute_external_script`):
  - does **not** change the `external scripts enabled` setting;
  - if already enabled:
    - attempts `whoami` via R;
    - falls back to Python if R fails;
  - records which language worked and the command output.
- **SQL Agent CmdExec surface** (if `msdb` is available):
  - checks membership in `SQLAgentUserRole`, `SQLAgentReaderRole`, `SQLAgentOperatorRole`;
  - counts job steps with `subsystem = 'CmdExec'`;
  - flags the presence of a potentially dangerous CmdExec surface.
- **Linked servers**:
  - counts linked servers with `is_linked = 1` and `is_rpc_out_enabled = 1`.

All temporary changes to configuration (`xp_cmdshell`, `Ole Automation Procedures`, `show advanced options`) are reverted to original values when possible.

### SQL Server service account analysis

- Reads SQL Server service account from `sys.dm_server_services`.
- Classifies the service account as:
  - built-in (`NT AUTHORITY\...`, `NT SERVICE\...`, `LocalSystem`, `Local Service`, `Network Service`), or
  - domain/machine account (`DOMAIN\User`).
- For domain accounts, attempts to check if the service account is a member of **Domain Admins** using `System.DirectoryServices.AccountManagement`.

### Credential grouping

- After probes, groups successful connections into **credential groups**:
  - key: `(server data source, login, password)` (for SQL auth) or `(server data source, IntegratedSecurity)` for Windows auth.
- Each `CredentialGroup` tracks:
  - server;
  - login display (e.g. `sa`, `IntegratedSecurity`);
  - raw password (for internal processing) and a separate display value (can be redacted in reports);
  - list of `ConnectionCheckResult` instances;
  - list of file paths where these credentials were found.

### Local administrator password reuse checks

> This feature is **disabled by default** and must be explicitly enabled.

When enabled:

- Enumerates **local administrator accounts** on the machine using `System.DirectoryServices.AccountManagement` on the local `Administrators` group (non-recursive).
- Ensures `.\\Administrator` is always present as a fallback target.
- For each **distinct password** coming from:
  - credential groups (SQL connection strings with SQL auth),
  - password-like attributes in configuration files,
- The tool:
  - calls `LogonUser(domain, user, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT)` for each local admin account;
  - records if any admin account accepted the password;
  - caches results per password to avoid repeated logon attempts.

The report highlights any cases where a password from configs is also valid for a local administrator account as **CRITICAL**.

### Reporting

- Generates a **plain text report** (UTF-8) in a single file (default: `sqlout.txt` in the tool directory).
- Contains:
  1. Summary header (timestamp, root scope, total credential groups).
  2. Detailed information for each **credential group**:
     - server, login, password (optionally redacted);
     - SQL identity (`SYSTEM_USER`, `ORIGINAL_LOGIN()`);
     - example successful connection string;
     - whether password matches any local admin (if enabled);
     - file locations where the credentials were found;
     - SQL Server IP and “local/remote” classification;
     - SQL service account, domain / Domain Admin status;
     - status and output for:
       - `xp_cmdshell`,
       - OLE Automation `whoami`,
       - external scripts `whoami`,
       - SQL Agent CmdExec surface,
       - linked servers with RPC OUT;
     - aggregated error details (if any).
  3. A section with **extra password attributes**:
     - password-like attributes from configs that matched local admin accounts.

---

## How it works (high level architecture)

The tool is structured into several layers:

- **CLI layer (`Cli`)**
  - `Program` – entry point.
  - `AppOptions` – strongly typed options with safe defaults.
  - `AppOptionsParser` – command-line parsing, profiles, and `--help`.

- **File scanning (`FileScanning`)**
  - `ConfigFileScanner` – iterates over directories, filters config-like files.
  - `ConfigContentExtractor` – reads each file once, extracting:
    - connection strings,
    - password-like attributes (via regex).

- **SQL layer (`Sql`)**
  - `ConnectionGrouper` – groups connection strings by `(server, login)` for efficient probing.
  - `SqlProbe` – performs active SQL checks and collects `ConnectionCheckResult`.
  - `CredentialGrouper` – groups `ConnectionCheckResult` into `CredentialGroup` by `(server, login, password)`.

- **Security layer (`Security`)**
  - `AdminPasswordTester` – enumerates local admins (non-recursive) and checks password reuse using `LogonUser`.

- **Reporting (`Reporting`)**
  - `TextReportWriter` – converts `CredentialGroup` and `PasswordCandidate` data into a text report.
  - `ReportOptions`, `AuditReportInput` – simple DTOs for decoupling reporting from the pipeline.

- **Pipeline (`Pipeline`)**
  - `AuditPipeline` – orchestrates:
    - file scanning,
    - content extraction,
    - SQL probes,
    - credential grouping,
    - admin password reuse checks (optional),
    - report generation.

This structure is intentionally modular to keep code testable and maintainable.

---

## Requirements

- **OS:** Windows (desktop/server).
- **Runtime:** .NET Framework 4.8 (or compatible).
- **Permissions:**
  - read access to the directories being scanned;
  - network access to the SQL Servers referenced in configs;
  - SQL permissions sufficient to:
    - connect to the target databases,
    - query metadata like `sys.configurations`, `sys.dm_server_services`, `sys.servers`, `msdb` tables;
    - `sp_configure` / `RECONFIGURE` / `xp_cmdshell` / OLE / `sp_execute_external_script` depending on which features you enable.
  - For admin password reuse checks:
    - rights to call `LogonUser` for local administrator accounts.

The tool is intended to be used by administrators and security engineers who **already have** appropriate permissions in the environment.

---

## Usage

### Basic usage

Compile the project, then run:

```bash
SqlServerSecurityAudit.exe
```

### By default this will

- scan all suitable drives;
- enable active SQL checks (connect and query);
- **not** change SQL Server configuration (`xp_cmdshell`, OLE);
- **not** test passwords against local administrators;
- redact passwords in the report;
- write `sqlout.txt` to the tool directory.

---

## Profiles

You can control behaviour using profiles:

### `--profile passive`

- No SQL connections (file-based analysis only).

### `--profile standard`

- Active SQL checks enabled.
- No changes to SQL configuration.
- No admin password reuse checks.

(This is effectively the default profile.)

### `--profile deep`

- Active SQL checks enabled.
- Allows toggling `xp_cmdshell` and `Ole Automation Procedures`.
- Enables admin password reuse checks.

---

### Examples

```bash
# Passive, file-only audit of a specific root
SqlServerSecurityAudit.exe --profile passive --root C:\Projects
```

## Flags (override profile defaults)

### Common options

- `--root <path>`  
  Add a root directory to scan (can be used multiple times).

- `--scan-all` / `--no-scan-all`  
  Enable or disable automatic scanning of all suitable drives when no root is specified.

- `--output <file>` or `-o <file>`  
  Set report file name (default: `sqlout.txt` in the tool directory).

### SQL behaviour

- `--active-sql` / `--no-active-sql`  
  Enable or disable active SQL checks (connections + probes).

- `--xp-toggle` / `--no-xp-toggle`  
  Allow or forbid changing `xp_cmdshell` configuration via `sp_configure`.

- `--ole-toggle` / `--no-ole-toggle`  
  Allow or forbid changing `Ole Automation Procedures` configuration.

### Security checks

- `--admin-reuse` / `--no-admin-reuse`  
  Enable or disable testing passwords against local administrator accounts.

- `--show-passwords` / `--no-show-passwords`  
  Show raw passwords in the report or redact them (default: redacted).

## Help


```bash
SqlServerSecurityAudit.exe --help
SqlServerSecurityAudit.exe -?
```
## Report format

The report is a UTF-8 text file with several sections.

### Example structure

```bash
=== SQL Server security audit report ===
Timestamp: 2025-01-01 12:34:56
Root scope: C:\Projects
Total credential groups: 3

=== SQL Server command execution surface (grouped by server-login-password) ===

------------------------------------------------------------
Server data source: SQLSERVER01
Login: sa
Password: ******** (redacted)
Uses Windows auth: no
Actual SYSTEM_USER (inside SQL): dbo
Actual ORIGINAL_LOGIN() (inside SQL): sa
Example successful connection string:
Server=SQLSERVER01;Database=ProdDb;User Id=sa;Password=SuperSecret123;

Password matches at least one local Administrator account: YES (CRITICAL)
Matched admin account(s): SERVER01\Administrator

Found in 2 location(s):
  - C:\Projects\App1\web.config
  - C:\Projects\App2\appsettings.json
SQL Server IP: 10.0.0.10
SQL Server location: remote
SQL Server service account: DOMAIN\sql_svc
Service account is domain account: yes
Service account is Domain Admin: no

xp_cmdshell whoami: SUCCESS
xp_cmdshell whoami output: DOMAIN\sql_svc

OLE Automation whoami tried: yes
OLE Automation whoami: ERROR or not available

External scripts enabled: yes
External scripts whoami: SUCCESS via Python
External scripts whoami output: DOMAIN\sql_svc

SQL Agent CmdExec surface present: YES
SQL Agent CmdExec steps count: 5
SQL Agent roles: SQLAgentReaderRole,SQLAgentOperatorRole

Linked servers with RPC OUT: 2

Details: xp_cmdshell enable/disable messages, external script errors, etc.

=== Extra password attributes with 'passw' checked against local administrators ===

Total matching password attributes: 1

------------------------------------------------------------
File: C:\Projects\App1\appsettings.Development.json
Attribute name: DbAdminPassword
Password value: SuperSecret123
Source line snippet: "DbAdminPassword": "SuperSecret123",
Matches local admin account(s): SERVER01\Administrator
Admin password check details: No admin accounts accepted this password.
```


The exact layout may evolve, but the main idea is:

- group by credentials to avoid noisy repetition;
- clearly flag dangerous combinations like:
  - `xp_cmdshell` + high-privileged service account;
  - SQL login passwords reused as local admin passwords.

---

## Security & legal notes

This tool is intended for **defensive security** and **configuration auditing** in environments where you are authorized to operate.

It can:

- change SQL Server configuration (when allowed by options) via `sp_configure`;
- execute commands through `xp_cmdshell`, OLE Automation, and external scripts;
- attempt logons for local administrator accounts.

Always:

- run it in accordance with your organization's policies;
- obtain proper approvals before running in production environments;
- test in non-production first.

> **Use at your own risk.**  
> The author is not responsible for any damage, misconfiguration, or policy violations caused by misuse of this tool.

## Roadmap / ideas

Potential future improvements:

- JSON / HTML report formats.
- More granular control over which SQL checks are executed.
- Better detection of configuration files (custom patterns).
- Optional recursive expansion of domain groups for admin enumeration (behind a dedicated flag).
- Unit tests for configuration parsing and grouping logic.
