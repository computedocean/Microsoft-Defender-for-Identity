# Get-gMSAPermissionsOnUser.ps1

The `Get-gMSAPermissionsOnUser.ps1` script inspects the Active Directory ACL of a target user object and returns every permission that a specified **group Managed Service Account (gMSA)** has on it, either assigned or inherited, directly or via group memberships.

It covers the following permission sources:

- **Direct** — ACEs explicitly assigned to the gMSA itself
- **Group** — ACEs assigned to any AD group the gMSA belongs to (full recursive / nested membership expansion via `memberOf`)
- **Primary group** — ACEs assigned to the gMSA's primary group (resolved from `primaryGroupID`; typically `Domain Computers`)
- **Built-in / implicit** — ACEs assigned to well-known identities every authenticated account qualifies for (`Everyone`, `Authenticated Users`, `NT AUTHORITY\SELF`, `CREATOR OWNER`, `This Organization`), as well as any `BUILTIN\` or domain group in the ACL that the gMSA is actually a member of — groups the gMSA does **not** belong to are never evaluated

The script emits `PSCustomObject` result objects to the pipeline — no host output — so results can be freely piped, filtered, or formatted by the caller.

Each output object contains the following properties:

| Property | Description |
|---|---|
| `Source` | Identity that carries the ACE: the gMSA's own `SamAccountName`, a group name, or a well-known identity label such as `Everyone` |
| `IsInherited` | `$true` if the ACE was inherited from a parent OU or container; `$false` if it was set directly on the user object |
| `AccessControlType` | `Allow` or `Deny` |
| `ActiveDirectoryRights` | The AD right(s) granted or denied (e.g. `ReadProperty`, `WriteProperty`, `GenericAll`) |
| `ObjectType` | Attribute or extended right the ACE targets, resolved from the schema GUID to a friendly name; `All Objects` if the GUID is empty |
| `InheritedObjectType` | Object class the ACE propagates to, resolved from schema GUID; `Any` if the GUID is empty |
| `InheritanceType` | Scope of inheritance (`None`, `All`, `Descendents`, `SelfAndChildren`, etc.) |

```txt
NAME
    .\Get-gMSAPermissionsOnUser.ps1

SYNOPSIS
    Returns all AD permissions a gMSA holds on a target user object as an array
    of custom objects.

SYNTAX
    .\Get-gMSAPermissionsOnUser.ps1 [-TargetUser] <String> [-ServiceAccount] <String>
        [[-Server] <String>] [-Verbose] [<CommonParameters>]

.DESCRIPTION
    Inspects the ACL of the target user's AD object and emits one PSCustomObject
    per matching ACE, covering every identity channel through which the gMSA can
    exercise a permission:

      • Direct        — ACE assigned explicitly to the gMSA.
      • Group         — ACE assigned to an AD group the gMSA belongs to
                        (recursive / nested membership via memberOf).
      • PrimaryGroup  — ACE assigned to the gMSA's primary group
                        (resolved from primaryGroupID; typically Domain Computers).
      • BuiltIn       — ACE assigned to a well-known implicit identity the gMSA
                        qualifies for (Everyone, Authenticated Users, SELF, etc.)
                        OR to a built-in/domain group the gMSA is actually a member
                        of (checked against the gMSA's resolved membership set —
                        groups the gMSA does NOT belong to are never evaluated).

    No output is written to the host; the script emits only the result objects so
    callers can pipe, filter, or format them freely.

.OUTPUTS
    PSCustomObject with properties:
        Source                — Identity that carries the ACE (gMSA SamAccountName,
                                group name, or well-known identity label).
        IsInherited           — Whether the ACE was inherited from a parent container.
        AccessControlType     — Allow or Deny.
        ActiveDirectoryRights — The AD right(s) granted/denied.
        ObjectType            — Attribute or extended right the ACE targets
                                (resolved from schema GUID; "All Objects" if empty).
        InheritedObjectType   — Object class the ACE propagates to
                                (resolved from schema GUID; "Any" if empty).
        InheritanceType       — Scope of inheritance (None, All, Descendents, etc.).

PARAMETERS
    -TargetUser <String>
        The SamAccountName, DistinguishedName, or UserPrincipalName of the AD user
        whose ACL will be inspected.

        Required?                    true
        Position?                    1
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -ServiceAccount <String>
        The SamAccountName or DistinguishedName of the gMSA to evaluate
        (e.g. "mdiSvc01$").

        Required?                    true
        Position?                    2
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -Server <String>
        Domain controller to query. Defaults to the current logon server.

        Required?                    false
        Position?                    3
        Default value
        Accept pipeline input?       false
        Accept wildcard characters?  false

NOTES
    Requires:
      - ActiveDirectory PowerShell module (RSAT-AD-PowerShell)
      - Sufficient privileges to read the target user's ACL in Active Directory
        (Domain Admins or equivalent delegated read access)

    -------------------------- EXAMPLE 1 --------------------------

    PS C:\>.\Get-gMSAPermissionsOnUser.ps1 -TargetUser "john.doe" -ServiceAccount "mdiSvc01$"

    Returns all ACEs the gMSA mdiSvc01$ can exercise on john.doe, across all
    identity channels.

    -------------------------- EXAMPLE 2 --------------------------

    PS C:\>.\Get-gMSAPermissionsOnUser.ps1 -TargetUser "john.doe" -ServiceAccount "mdiSvc01$" |
        Where-Object AccessControlType -eq 'Allow' |
        Format-Table -AutoSize

    Returns only Allow ACEs and displays them as a formatted table.

    -------------------------- EXAMPLE 3 --------------------------

    PS C:\>.\Get-gMSAPermissionsOnUser.ps1 -TargetUser "john.doe" -ServiceAccount "mdiSvc01$" |
        Where-Object { $_.ActiveDirectoryRights -match 'Write' }

    Returns only ACEs that grant some form of write access.

    -------------------------- EXAMPLE 4 --------------------------

    PS C:\>$results = .\Get-gMSAPermissionsOnUser.ps1 -TargetUser "john.doe" -ServiceAccount "mdiSvc01$"
    PS C:\>$results | Group-Object Source | Select-Object Name, Count

    Groups results by the identity source to get a quick count of ACEs per
    identity channel.

    -------------------------- EXAMPLE 5 --------------------------

    PS C:\>.\Get-gMSAPermissionsOnUser.ps1 -TargetUser "john.doe" -ServiceAccount "mdiSvc01$" `
        -Server "DC01.corp.local" -Verbose
    VERBOSE: Resolving target user 'john.doe'...
    VERBOSE:   -> CN=John Doe,OU=Users,DC=corp,DC=local
    VERBOSE: Resolving gMSA 'mdiSvc01$'...
    VERBOSE:   -> CN=mdiSvc01,CN=Managed Service Accounts,DC=corp,DC=local
    VERBOSE: Expanding recursive group memberships...
    VERBOSE:   Primary group added: Domain Computers
    VERBOSE:   Total explicit groups: 3
    VERBOSE: Reading ACL for 'CN=John Doe,OU=Users,DC=corp,DC=local'...
    VERBOSE: Building schema/extended-rights GUID map...
    VERBOSE:   Built-in/domain group matched via membership: BUILTIN\Pre-Windows 2000 Compatible Access
```

## Prerequisites

| Requirement | Details |
|---|---|
| PowerShell | Windows PowerShell 5.1 or PowerShell 7+ |
| ActiveDirectory module | Install via `Add-WindowsFeature RSAT-AD-PowerShell` (servers) or **Optional Features → RSAT: Active Directory** (Windows 10/11) |
| AD read access | The running account must have permission to read the target user's object ACL and to query group memberships and the AD schema |
