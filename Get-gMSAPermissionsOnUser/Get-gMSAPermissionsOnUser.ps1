<#
.SYNOPSIS
    Returns all AD permissions a gMSA holds on a target user object as an array
    of custom objects.

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

.PARAMETER TargetUser
    SamAccountName, DistinguishedName, or UPN of the AD user to inspect.

.PARAMETER ServiceAccount
    SamAccountName or DistinguishedName of the gMSA (e.g. "mdiSvc01$").

.PARAMETER Server
    Optional. Domain controller to query. Defaults to the logon server.

.EXAMPLE
    .\Get-gMSAPermissionsOnUser.ps1 -TargetUser "john.doe" -ServiceAccount "mdiSvc01$"

.EXAMPLE
    .\Get-gMSAPermissionsOnUser.ps1 -TargetUser "john.doe" -ServiceAccount "mdiSvc01$" -Server "DC01.corp.local" -Verbose

.NOTES
    Requires:
      - ActiveDirectory PowerShell module (RSAT)
      - Read access to the target user's ACL in AD
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]  [string]$TargetUser,
    [Parameter(Mandatory = $true)]  [string]$ServiceAccount,
    [Parameter(Mandatory = $false)] [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Helper: schema + extended-rights GUID -> name map ────────────────────
function Get-SchemaGuidMap {
    param([hashtable]$SplatAD)
    $map = @{}
    try {
        $rootDSE = Get-ADRootDSE @SplatAD
        $schemaPath = $rootDSE.schemaNamingContext
        $extRightsPath = "CN=Extended-Rights,$($rootDSE.configurationNamingContext)"

        Get-ADObject -SearchBase $schemaPath -LDAPFilter '(schemaIDGUID=*)' `
            -Properties schemaIDGUID, lDAPDisplayName @SplatAD |
            ForEach-Object {
                $g = [System.Guid]$_.schemaIDGUID
                if (-not $map.ContainsKey($g)) { $map[$g] = $_.lDAPDisplayName }
            }

        Get-ADObject -SearchBase $extRightsPath -LDAPFilter '(rightsGuid=*)' `
            -Properties rightsGuid, displayName @SplatAD |
            ForEach-Object {
                try {
                    $g = [System.Guid]::new($_.rightsGuid)
                    if (-not $map.ContainsKey($g)) { $map[$g] = $_.displayName }
                } catch { }
            }
    } catch { Write-Verbose "Get-SchemaGuidMap: $_" }
    return $map
}
#endregion

#region ── Helper: recursive memberOf expansion ─────────────────────────────────
function Get-AllGroupMemberships {
    # Returns hashtable: DN -> SamAccountName for every group (transitive).
    param([string]$ObjectDN, [hashtable]$SplatAD)

    $visited = @{}
    $queue = [System.Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($ObjectDN)

    while ($queue.Count -gt 0) {
        $dn = $queue.Dequeue()
        try {
            $obj = Get-ADObject -Identity $dn -Properties memberOf @SplatAD -ErrorAction Stop
        } catch { Write-Verbose "Get-AllGroupMemberships: cannot read '$dn': $_"; continue }

        foreach ($groupDN in $obj.memberOf) {
            if ($visited.ContainsKey($groupDN)) { continue }
            try {
                $grp = Get-ADGroup -Identity $groupDN -Properties SamAccountName @SplatAD -ErrorAction Stop
                $visited[$groupDN] = $grp.SamAccountName
                $queue.Enqueue($groupDN)
            } catch {
                Write-Verbose "Get-AllGroupMemberships: cannot read group '$groupDN': $_"
                $visited[$groupDN] = $groupDN
            }
        }
    }
    return $visited
}
#endregion

#region ── Helper: resolve primaryGroupID RID -> SamAccountName ─────────────────
function Resolve-PrimaryGroup {
    param([int]$RID, [string]$DomainSID, [hashtable]$SplatAD)
    try {
        $sid = "$DomainSID-$RID"
        $grp = Get-ADGroup -Filter "objectSid -eq '$sid'" @SplatAD -ErrorAction Stop |
            Select-Object -First 1
        return $grp.SamAccountName
    } catch { Write-Verbose "Resolve-PrimaryGroup RID=$RID : $_"; return $null }
}
#endregion

#region ── Helper: resolve ACE GUID -> friendly name ────────────────────────────
function Resolve-Guid {
    param([System.Guid]$Guid, [hashtable]$GuidMap, [string]$EmptyLabel)
    if ($Guid -eq [System.Guid]::Empty) { return $EmptyLabel }
    if ($GuidMap.ContainsKey($Guid)) { return $GuidMap[$Guid] }
    return $Guid.ToString()
}
#endregion

#region ── Helper: emit one result object ───────────────────────────────────────
function New-Result {
    param($Ace, [string]$Source, [hashtable]$GuidMap)
    [PSCustomObject]@{
        Source                = $Source
        IsInherited           = $Ace.IsInherited
        AccessControlType     = $Ace.AccessControlType
        ActiveDirectoryRights = $Ace.ActiveDirectoryRights
        ObjectType            = Resolve-Guid $Ace.ObjectType          $GuidMap 'All Objects'
        InheritedObjectType   = Resolve-Guid $Ace.InheritedObjectType $GuidMap 'Any'
        InheritanceType       = $Ace.InheritanceType
    }
}
#endregion


#── Main ──────────────────────────────────────────────────────────────────────
if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
    throw 'ActiveDirectory module not found. Install RSAT or run on a domain controller.'
}
Import-Module ActiveDirectory -ErrorAction Stop
$splatAD = @{}
if ($Server) { $splatAD['Server'] = $Server }

#── Resolve target user ────────────────────────────────────────────────────────
Write-Verbose "Resolving target user '$TargetUser'..."
$userObj = Get-ADUser -Filter "SamAccountName -eq '$TargetUser' -or DistinguishedName -eq '$TargetUser' -or UserPrincipalName -eq '$TargetUser'" `
    -Properties DistinguishedName @splatAD | Select-Object -First 1
if (-not $userObj) { throw "Target user '$TargetUser' not found." }
Write-Verbose "  -> $($userObj.DistinguishedName)"

#── Resolve gMSA ──────────────────────────────────────────────────────────────
Write-Verbose "Resolving gMSA '$ServiceAccount'..."
$gmsaObj = Get-ADServiceAccount -Filter "SamAccountName -eq '$ServiceAccount' -or DistinguishedName -eq '$ServiceAccount'" `
    -Properties primaryGroupID @splatAD | Select-Object -First 1
if (-not $gmsaObj) { throw "gMSA '$ServiceAccount' not found." }
$gmsaSam = $gmsaObj.SamAccountName    # includes trailing '$'
Write-Verbose "  -> $($gmsaObj.DistinguishedName)"

#── Domain info ────────────────────────────────────────────────────────────────
$domainObj = Get-ADDomain @splatAD
$netbios = $domainObj.NetBIOSName
$domSID = $domainObj.DomainSID.Value

#── Build the full explicit membership set (memberOf, recursive) ───────────────
Write-Verbose 'Expanding recursive group memberships...'
$explicitGroups = Get-AllGroupMemberships -ObjectDN $gmsaObj.DistinguishedName -SplatAD $splatAD
# explicitGroups: DN -> SamAccountName

#── Resolve primary group and add it to the membership set ─────────────────────
if ($gmsaObj.primaryGroupID) {
    $pgSam = Resolve-PrimaryGroup -RID $gmsaObj.primaryGroupID -DomainSID $domSID -SplatAD $splatAD
    if ($pgSam -and ($explicitGroups.Values -notcontains $pgSam)) {
        # primaryGroupID group does not appear in memberOf, so add it manually
        $pgSID = "$domSID-$($gmsaObj.primaryGroupID)"
        $explicitGroups["PrimaryGroup:$pgSID"] = $pgSam
        Write-Verbose "  Primary group added: $pgSam"
    }
}

# Flat set of SamAccountNames the gMSA belongs to (used for built-in membership checks)
$memberOfSams = @($explicitGroups.Values)
Write-Verbose "  Total explicit groups: $($memberOfSams.Count)"

#── Well-known implicit identities ─────────────────────────────────────────────
# These apply unconditionally to every authenticated account (no membership check needed).
# Key = IdentityReference string as it appears in ACEs.
$unconditionalIdentities = @{
    'Everyone'                         = 'Everyone'
    'NT AUTHORITY\Authenticated Users' = 'Authenticated Users'
    'NT AUTHORITY\SELF'                = 'NT AUTHORITY\SELF'
    'CREATOR OWNER'                    = 'CREATOR OWNER'
    'NT AUTHORITY\This Organization'   = 'This Organization'
}

#── Read the ACL ───────────────────────────────────────────────────────────────
Write-Verbose "Reading ACL for '$($userObj.DistinguishedName)'..."
$acl = Get-Acl -Path "AD:\$($userObj.DistinguishedName)" -ErrorAction Stop

#── Build GUID map ─────────────────────────────────────────────────────────────
Write-Verbose 'Building schema/extended-rights GUID map...'
$guidMap = Get-SchemaGuidMap -SplatAD $splatAD

#── Build master identity -> Source label map ──────────────────────────────────
# Key   = IdentityReference.Value string (as stored in ACEs)
# Value = Source label for the output object
$identityMap = @{}

# 1. The gMSA itself
$identityMap["$netbios\$gmsaSam"] = $gmsaSam

# 2. Every explicit / primary group the gMSA is a member of
foreach ($sam in $memberOfSams) {
    $ref = "$netbios\$sam"
    if (-not $identityMap.ContainsKey($ref)) {
        $identityMap[$ref] = $sam
    }
}

# 3. Unconditional well-known identities (always apply)
foreach ($kvp in $unconditionalIdentities.GetEnumerator()) {
    if (-not $identityMap.ContainsKey($kvp.Key)) {
        $identityMap[$kvp.Key] = $kvp.Value
    }
}

# 4. Conditional built-in / domain groups:
#    Only add the identity if the gMSA is actually a member of that group.
#    We discover which BUILTIN\ and domain groups appear in the ACL, then
#    check whether the gMSA's resolved membership set includes them.
$aclIdentities = $acl.Access |
    Select-Object -ExpandProperty IdentityReference |
        Select-Object -ExpandProperty Value -Unique

foreach ($idVal in $aclIdentities) {
    if ($identityMap.ContainsKey($idVal)) { continue }   # already covered

    # Only consider BUILTIN\ groups and domain groups (skip NT AUTHORITY\ — handled above)
    $isBuiltin = $idVal -match '^BUILTIN\\'
    $isDomainGrp = $idVal -match "^$([regex]::Escape($netbios))\\"

    if (-not ($isBuiltin -or $isDomainGrp)) { continue }

    # Extract the SamAccountName portion after the backslash
    $sam = $idVal -replace '^[^\\]+\\', ''

    # Only add if the gMSA is actually a member of this group
    if ($memberOfSams -contains $sam) {
        $identityMap[$idVal] = $sam
        Write-Verbose "  Built-in/domain group matched via membership: $idVal"
    }
}

#── Emit one result object per matching ACE ────────────────────────────────────
foreach ($ace in $acl.Access) {
    $idVal = $ace.IdentityReference.Value
    if (-not $identityMap.ContainsKey($idVal)) { continue }

    New-Result -Ace $ace -Source $identityMap[$idVal] -GuidMap $guidMap
}