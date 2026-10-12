#requires -Version 5.1

<#
.SYNOPSIS
    Audit et offboarding : comptes AD, boites aux lettres, listes de distribution,
    delegations sur boites partagees et licences applicatives.

.DESCRIPTION
    Version 5.0 - toutes les analyses sont CIBLEES et SILENCIEUSES :
      - seuls les UPN trouves dans AD sont analyses dans Exchange, et seuls
        ceux qui ont un objet Exchange sont recherches dans les DL et les BAL
        partagees. Si aucun utilisateur n'est concerne, le scan est saute (la
        connexion Exchange Online elle-meme n'est ouverte que si necessaire) ;
      - les DL d'un utilisateur sont obtenues par un filtre serveur
        (Members -eq <DN>) : plus d'inventaire de toutes les DL du tenant ;
      - le parcours des BAL partagees n'affiche rien, sauf quand un
        utilisateur demande y est delegue. Les BAL illisibles sont resumees
        en une seule ligne a la fin.

    Ordre d'execution : delegations BAL, DL, groupes AD, puis desactivation.
    La desactivation n'a lieu que si les etapes precedentes ont reussi (voir
    $DisableAccountOnPartialFailure) : un echec partiel laisse un compte
    actif et rejouable.

.PARAMETER UserPrincipalName
    UPN a traiter. Sans ce parametre ni -InputFile, le script les demande.

.PARAMETER InputFile
    CSV (colonne UPN / UserPrincipalName / Mail, sinon la premiere colonne ;
    separateur ; , ou tabulation detecte) ou TXT (un UPN par ligne, # = commentaire).

.PARAMETER ExportRoot
    Dossier du rapport CSV.

.PARAMETER ShowProgress
    Affiche les barres de progression des analyses (masquees par defaut).

.EXAMPLE
    .\Offboarding-Audit.ps1 -InputFile C:\Temp\departs.csv -WhatIf

.NOTES
    Version    : 5.0
    Prerequis  : ActiveDirectory, ExchangeOnlineManagement v2+
    Compatible : Windows PowerShell 5.1
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string[]]$UserPrincipalName,
    [string]$InputFile,
    [string]$ExportRoot = 'C:\Temp\AD\Logs\AD+DL',
    [switch]$ShowProgress
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if (-not $ShowProgress) { $ProgressPreference = 'SilentlyContinue' }

# ====================================================================
# CONFIGURATION
# ====================================================================
$ScanInboxRules                 = $true
$ScanSharedMailboxPermissions   = $true
$SharedMailboxPermissionTypes   = @('FullAccess', 'SendAs', 'SendOnBehalf')
$DisableAccountOnPartialFailure = $false

$ADChunkSize                    = 100
$BulkMailboxThreshold           = 300   # au-dela, un seul Get-EXOMailbox pour tout le tenant

$MaxRetries                     = 3
$RetryBaseDelayMs               = 2000

$TargetSecurityGroupName        = 'GrpSecu-Utilisateurs_POWERPDF'

$ProtectedGroupPatterns         = @(
    ',CN=Builtin,',
    '^CN=Domain Users,',
    '^CN=Utilisateurs du domaine,'
)

$LicenseFiles = @(
    [pscustomobject]@{ Name = 'Autodesk'; Path = (Join-Path $env:USERPROFILE 'Downloads\users-Autodesk (1).xlsx') },
    [pscustomobject]@{ Name = 'Adobe';    Path = (Join-Path $env:USERPROFILE 'Downloads\Licence-Adobe (1).xlsx') }
)

# Proprietes hors jeu par defaut de Get-EXOMailbox (UPN, SMTP, Alias, Name,
# DN, Guid, EmailAddresses, RecipientTypeDetails... sont toujours renvoyes).
$MailboxProperties   = @('LitigationHoldEnabled', 'InPlaceHolds', 'ForwardingAddress',
                         'ForwardingSmtpAddress', 'DeliverToMailboxAndForward')

$UpnPattern          = '^[^@\s]+@[^@\s]+\.[^@\s]+$'
$EmailRegex          = [regex]'[\w.+-]+@[\w-]+(?:\.[\w-]+)+'

# Erreurs definitives : inutile de reessayer (un UPN absent coutait 12 s).
$NonRetryablePattern = "couldn't be found|could not be found|can't be found|cannot find|not found|" +
                       "impossible de trouver|introuvable|n'existe pas|isn't a member|is not a member|" +
                       "n'est pas membre|already|existe d.j.|synchroni[sz]|access ?denied|acc.s refus.|" +
                       "sufficient permission|insufficient|droits? insuffisants|unauthorized|non autoris|" +
                       "isn't valid|n'est pas valide|cannot bind|impossible de lier"

# ====================================================================
# UTILITAIRES
# ====================================================================

# Acces sur a une propriete : indispensable sous Set-StrictMode 2.0, les objets
# Exchange n'exposant pas les memes proprietes selon le RecipientTypeDetails.
function Get-Prop {
    param($InputObject, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    $p = $InputObject.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

# Valeurs non vides d'une propriete, scalaire ou multivaluee.
# @($null).Count vaut 1 : c'est ce qui faisait signaler chaque regle Inbox.
function Get-PropValues {
    param($InputObject, [Parameter(Mandatory)][string]$Name)
    return @(Get-Prop $InputObject $Name | Where-Object { $null -ne $_ -and "$_".Trim() })
}

function ConvertTo-IdentityKey {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    return (($Value -replace '^(?i)smtp:', '').Trim().ToLowerInvariant())
}

# Echappement RFC 4515. -replace travaille toujours en [string] : avec
# .Replace([char]0,'\00') PowerShell resout Replace(char,char) et echoue.
function ConvertTo-LdapFilterValue {
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '' }
    return ($Value -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29' -replace "`0", '\00')
}

# Nom d'un groupe extrait de son DN (CN = Name en AD) : evite un Get-ADGroup par groupe.
function Get-NameFromDN {
    param([string]$DistinguishedName)
    if ($DistinguishedName -match '^CN=((?:\\.|[^,\\])+)') { return ($Matches[1] -replace '\\(.)', '$1') }
    return $DistinguishedName
}

function Test-IsProtectedGroupDN {
    param([string]$DistinguishedName)
    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return $true }
    foreach ($pattern in $ProtectedGroupPatterns) {
        if ($DistinguishedName -match $pattern) { return $true }
    }
    return $false
}

function Join-Values {
    param([object[]]$Values)
    return (@($Values | Where-Object { $null -ne $_ -and "$_".Trim() } |
              ForEach-Object { "$_".Trim() } | Sort-Object -Unique) -join ' | ')
}

# Les blocs passes ici voient les variables de l'appelant : ne pas y utiliser
# les noms $attempt, $message, $permanent ni $delay.
function Invoke-WithRetry {
    param([Parameter(Mandatory)][scriptblock]$ScriptBlock)
    $attempt = 0
    while ($true) {
        $attempt++
        try { return (& $ScriptBlock) }
        catch {
            $message   = $_.Exception.Message
            $permanent = ("$($_.CategoryInfo.Category)" -eq 'ObjectNotFound') -or ($message -match $NonRetryablePattern)
            if ($permanent -or $attempt -ge $MaxRetries) { throw }
            $delay = $RetryBaseDelayMs * [math]::Pow(2, $attempt - 1)
            if ($message -match 'throttl|429|too many|micro delay|busy') { $delay = [math]::Max($delay, 5000) }
            Write-Verbose ("Tentative {0}/{1} en echec, nouvel essai dans {2} ms : {3}" -f $attempt, $MaxRetries, $delay, $message)
            Start-Sleep -Milliseconds ([int]$delay)
        }
    }
}

function Write-ScanProgress {
    param([string]$Activity, [int]$Current, [int]$Total, [Diagnostics.Stopwatch]$Stopwatch, [string]$CurrentItem = '')
    if ($ProgressPreference -eq 'SilentlyContinue' -or $Total -le 0) { return }
    $status = "$Current / $Total"
    # $Current est l'element en cours : $Current - 1 sont termines.
    if ($Current -gt 1 -and $Current -lt $Total) {
        $remaining = [int][math]::Floor($Stopwatch.Elapsed.TotalSeconds / ($Current - 1) * ($Total - $Current + 1))
        $status += ' - ETA {0:00}:{1:00}' -f [math]::Floor($remaining / 60), ($remaining % 60)
    }
    if ($CurrentItem) { $status += " - $CurrentItem" }
    Write-Progress -Activity $Activity -Status $status -PercentComplete ([math]::Min(100, $Current * 100 / $Total))
}

function Read-Choice {
    param([Parameter(Mandatory)][string]$Prompt, [string[]]$Choices = @('O', 'N'))
    do {
        $raw = Read-Host $Prompt
        if ($null -eq $raw) { throw 'Saisie interrompue.' }
        $answer = $raw.Trim().ToUpperInvariant()
    } until ($Choices -contains $answer)
    return $answer
}

# ====================================================================
# SAISIE
# ====================================================================

function Get-RequestedUpns {
    param([string[]]$Values, [string]$Path)

    if (-not $Values -and -not $Path) {
        $saisie = "$(Read-Host 'Entrez les UPN separes par des virgules, ou le chemin d''un fichier CSV/TXT')".Trim().Trim('"')
        $isFile = $false
        try { $isFile = Test-Path -LiteralPath $saisie -PathType Leaf } catch { $isFile = $false }
        if ($isFile) { $Path = $saisie } else { $Values = @($saisie) }
    }

    if ($Path) {
        $lines = @(Get-Content -LiteralPath $Path | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' })
        if ($lines.Count -and [IO.Path]::GetExtension($Path) -eq '.csv') {
            $delim = ';'
            foreach ($d in ';', ',', "`t") { if ($lines[0].Contains($d)) { $delim = $d; break } }

            if ($lines[0] -match '@') {
                # Pas d'en-tete : sinon le premier UPN servait de nom de colonne et etait perdu.
                $Values = @($lines | ForEach-Object { ($_ -split [regex]::Escape($delim))[0] })
            }
            else {
                $rows = @($lines | ConvertFrom-Csv -Delimiter $delim)
                $Values = @()
                if ($rows.Count) {
                    $cols = @($rows[0].PSObject.Properties | ForEach-Object { $_.Name })
                    $col  = @($cols | Where-Object { $_ -match '^(userprincipalname|upn|e-?mail|mail|adresse)' }) + $cols | Select-Object -First 1
                    $Values = @($rows | ForEach-Object { $_.$col })
                }
            }
        }
        else { $Values = $lines }
    }

    $tokens  = @($Values | ForEach-Object { "$_" -split '[,;\s]+' } |
                 ForEach-Object { $_ -replace '^[''"]+|[''"]+$', '' } | Where-Object { $_ })
    $invalid = @($tokens | Where-Object { $_ -notmatch $UpnPattern })
    if ($invalid.Count) { Write-Warning ('Entree(s) ignoree(s), UPN invalide : ' + ($invalid -join ', ')) }
    return @($tokens | Where-Object { $_ -match $UpnPattern } | Sort-Object -Unique)
}

function New-WorkItem {
    param([Parameter(Mandatory)][string]$Upn)
    [pscustomobject]@{
        UPN                              = $Upn
        Key                              = $Upn.ToLowerInvariant()
        ADUser                           = $null
        ADGroupDNs                       = @()
        IsMemberOfPowerPDFGroup          = $false
        Mailbox                          = $null
        Recipient                        = $null      # la BAL, ou a defaut le destinataire (MailUser...)
        ExchangeId                       = $Upn       # adresse SMTP principale une fois resolue
        Addresses                        = @($Upn.ToLowerInvariant())
        InboxRuleFindings                = @()
        DLEntries                        = @()
        SharedMailboxPermissions         = @()
        SharedMailboxPermissionsToRemove = @()
        SharedMailboxDecision            = ''
        Licenses                         = @()
        Anomalies                        = @()
        Errors                           = @()
        Journal                          = @()
        DecisionAnomalies                = ''
        DecisionGlobale                  = ''
        DateDecision                     = ''
        StatutExecution                  = 'Non execute'
    }
}

# ====================================================================
# ACTIVE DIRECTORY
# ====================================================================

function Resolve-ADAccounts {
    param([Parameter(Mandatory)][object[]]$Items)

    $byKey = @{}
    foreach ($it in $Items) { $byKey[$it.Key] = $it }

    for ($i = 0; $i -lt $Items.Count; $i += $ADChunkSize) {
        $chunk  = @($Items[$i..([math]::Min($i + $ADChunkSize, $Items.Count) - 1)])
        $parts  = @($chunk | ForEach-Object { '(userPrincipalName={0})' -f (ConvertTo-LdapFilterValue $_.UPN) })
        $filter = if ($parts.Count -eq 1) { $parts[0] } else { '(|{0})' -f ($parts -join '') }

        try { $found = @(Get-ADUser -LDAPFilter $filter -Properties MemberOf -ErrorAction Stop) }
        catch {
            Write-Verbose "Lot AD en echec, repli unitaire : $($_.Exception.Message)"
            $found = @(foreach ($it in $chunk) {
                try { Get-ADUser -LDAPFilter ('(userPrincipalName={0})' -f (ConvertTo-LdapFilterValue $it.UPN)) -Properties MemberOf -ErrorAction Stop }
                catch { $it.Errors += "Lecture AD impossible : $($_.Exception.Message)" }
            })
        }

        foreach ($u in $found) {
            $k = "$($u.UserPrincipalName)".ToLowerInvariant()
            if ($byKey.ContainsKey($k)) { $byKey[$k].ADUser = $u }
        }
    }

    foreach ($it in $Items) {
        if ($it.ADUser) { $it.ADGroupDNs = @(Get-PropValues $it.ADUser 'MemberOf'); continue }
        if (-not @($it.Errors).Count) { $it.Errors += "Utilisateur AD non trouve : $($it.UPN)" }
        $it.StatutExecution = 'Ignore (compte AD introuvable)'
    }
}

# ====================================================================
# EXCHANGE : BOITES AUX LETTRES, REGLES INBOX, DL
# ====================================================================

function Add-MailboxAnomalies {
    param([Parameter(Mandatory)]$Item)
    $m = $Item.Mailbox

    if (Get-Prop $m 'LitigationHoldEnabled') { $Item.Anomalies += '[!] LitigationHoldEnabled = True' }
    $holds = @(Get-PropValues $m 'InPlaceHolds')
    if ($holds.Count) { $Item.Anomalies += '[!] InPlaceHolds : ' + ($holds -join ', ') }
    foreach ($p in 'ForwardingAddress', 'ForwardingSmtpAddress') {
        $v = Get-Prop $m $p
        if ($v) { $Item.Anomalies += "[!] $p : $v" }
    }
    if (Get-Prop $m 'DeliverToMailboxAndForward') { $Item.Anomalies += '[!] DeliverToMailboxAndForward = True' }
    $rtd = "$(Get-Prop $m 'RecipientTypeDetails')"
    if ($rtd -and $rtd -ne 'UserMailbox') { $Item.Anomalies += "[!] Type de boite : $rtd" }

    if (-not $ScanInboxRules) { return }
    try {
        foreach ($rule in @(Invoke-WithRetry { Get-InboxRule -Mailbox $Item.ExchangeId -ErrorAction Stop -WarningAction SilentlyContinue })) {
            # SendTo n'existe pas sur Get-InboxRule : voici les trois vrais vecteurs.
            $vectors = @('RedirectTo', 'ForwardTo', 'ForwardAsAttachmentTo' | Where-Object { @(Get-PropValues $rule $_).Count })
            if ($vectors.Count) { $Item.InboxRuleFindings += "Regle '$($rule.Name)' : $($vectors -join ', ')" }
        }
        if (@($Item.InboxRuleFindings).Count) {
            $Item.Anomalies += '[!] Regles Inbox avec redirection : ' + (@($Item.InboxRuleFindings) -join ' ; ')
        }
    }
    catch { $Item.Anomalies += "[!] Lecture des regles Inbox impossible : $($_.Exception.Message)" }
}

function Resolve-ExchangeRecipients {
    param([Parameter(Mandatory)][object[]]$Items)

    $bulk = $null
    if ($Items.Count -ge $BulkMailboxThreshold) {
        try {
            $bulk = @{}
            foreach ($m in @(Get-EXOMailbox -ResultSize Unlimited -Properties $MailboxProperties -ErrorAction Stop -WarningAction SilentlyContinue)) {
                if ($m.UserPrincipalName) { $bulk["$($m.UserPrincipalName)".ToLowerInvariant()] = $m }
            }
        }
        catch { $bulk = $null; Write-Warning "Lecture globale des BAL impossible, repli unitaire : $($_.Exception.Message)" }
    }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $it = $Items[$i]
        Write-ScanProgress 'Analyse Exchange' ($i + 1) $Items.Count $sw $it.UPN

        # En mode bulk, une BAL absente du cache n'existe pas : pas de nouvel appel.
        if ($null -ne $bulk) { if ($bulk.ContainsKey($it.Key)) { $it.Mailbox = $bulk[$it.Key] } }
        else {
            try { $it.Mailbox = Invoke-WithRetry { Get-EXOMailbox -Identity $it.UPN -Properties $MailboxProperties -ErrorAction Stop -WarningAction SilentlyContinue } }
            catch { Write-Verbose "Get-EXOMailbox '$($it.UPN)' : $($_.Exception.Message)" }
        }

        $it.Recipient = $it.Mailbox
        if (-not $it.Mailbox) {
            $it.Anomalies += '[!] Aucune boite aux lettres Exchange'
            # Un MailUser peut rester membre de DL : Get-Recipient renvoie son DN.
            try { $it.Recipient = Invoke-WithRetry { Get-Recipient -Identity $it.UPN -ErrorAction Stop -WarningAction SilentlyContinue } }
            catch { Write-Verbose "Get-Recipient '$($it.UPN)' : $($_.Exception.Message)" }
        }
        if (-not $it.Recipient) { continue }

        $smtp = "$(Get-Prop $it.Recipient 'PrimarySmtpAddress')"
        if ($smtp) { $it.ExchangeId = $smtp }
        $it.Addresses = @(@($it.Key, $smtp) + @(Get-PropValues $it.Recipient 'EmailAddresses' | Where-Object { "$_" -match '^smtp:' }) |
                          ForEach-Object { ConvertTo-IdentityKey "$_" } | Where-Object { $_ } | Sort-Object -Unique)

        if ($it.Mailbox) { Add-MailboxAnomalies $it }
    }
    Write-Progress -Activity 'Analyse Exchange' -Completed
}

function Find-UserDistributionGroups {
    param([Parameter(Mandatory)][object[]]$Items)

    $sw = [Diagnostics.Stopwatch]::StartNew()
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $it = $Items[$i]
        Write-ScanProgress 'Listes de distribution' ($i + 1) $Items.Count $sw $it.UPN

        $dn = "$(Get-Prop $it.Recipient 'DistinguishedName')"
        if (-not $dn) { $it.Anomalies += '[!] DN Exchange inconnu : DL non verifiees'; continue }

        # Filtre serveur : seules les DL dont l'utilisateur est membre direct.
        $filter = "Members -eq '{0}'" -f ($dn -replace "'", "''")
        try {
            $it.DLEntries = @(Invoke-WithRetry { Get-DistributionGroup -Filter $filter -ResultSize Unlimited -ErrorAction Stop -WarningAction SilentlyContinue } |
                              Sort-Object DisplayName)
        }
        catch { $it.Anomalies += "[!] Lecture des DL impossible : $($_.Exception.Message)" }
    }
    Write-Progress -Activity 'Listes de distribution' -Completed
}

# ====================================================================
# BAL PARTAGEES : RECHERCHE CIBLEE ET SILENCIEUSE
# ====================================================================

<#
    Index inverse des identites des SEULS utilisateurs traites : cle normalisee
    -> cles des work items. Formes sous lesquelles Exchange renvoie un delegue :
      - FullAccess (User) et SendAs (Trustee) : UPN, SMTP, ou DOMAINE\sam
      - SendOnBehalf : Name / Identity, ou nom canonique .../Name
    DisplayName est exclu : non unique, il produisait des faux positifs.
#>
function New-TargetIdentityIndex {
    param([Parameter(Mandatory)][object[]]$Items)
    $index = @{}
    foreach ($it in $Items) {
        $raw = @($it.UPN) + @($it.Addresses) + @(Get-Prop $it.ADUser 'SamAccountName')
        foreach ($p in 'UserPrincipalName', 'Alias', 'Name', 'Identity', 'DistinguishedName', 'Guid', 'ExternalDirectoryObjectId') {
            $raw += "$(Get-Prop $it.Recipient $p)"
        }
        foreach ($value in $raw) {
            $k = ConvertTo-IdentityKey "$value"
            if (-not $k) { continue }
            if (-not $index.ContainsKey($k)) { $index[$k] = @() }
            if ($index[$k] -notcontains $it.Key) { $index[$k] += $it.Key }
        }
    }
    return $index
}

# Teste un delegue contre l'index, SANS appel Exchange. Les comptes systeme
# (NT AUTHORITY, SID orphelins) n'y figurent pas : aucun filtrage prealable utile.
function Find-TargetKeys {
    param($Delegate, [Parameter(Mandatory)][hashtable]$Index)
    $raw = "$Delegate".Trim()
    if (-not $raw) { return }
    $candidates = @($raw)
    if ($raw.Contains('\')) { $candidates += $raw.Split('\')[-1] }   # DOMAINE\sam -> sam
    if ($raw.Contains('/')) { $candidates += $raw.Split('/')[-1] }   # org/OU/Name -> Name
    foreach ($c in $candidates) {
        $k = ConvertTo-IdentityKey $c
        if ($k -and $Index.ContainsKey($k)) { return $Index[$k] }
    }
}

function Add-SharedMailboxDelegation {
    param([Parameter(Mandatory)]$Item, [Parameter(Mandatory)]$Mailbox, [string]$MailboxId, [string]$Type)
    if (@($Item.SharedMailboxPermissions | Where-Object { $_.MailboxId -eq $MailboxId -and $_.PermissionType -eq $Type }).Count) { return }
    $Item.SharedMailboxPermissions += [pscustomobject]@{
        MailboxId          = $MailboxId
        MailboxDisplayName = "$($Mailbox.DisplayName)"
        PermissionType     = $Type
    }
    # Seule sortie du scan : un utilisateur demande est concerne.
    Write-Host ("  [!] {0} : {1} sur '{2}' <{3}>" -f $Item.UPN, $Type, $Mailbox.DisplayName, $MailboxId) -ForegroundColor Red
}

# Renvoie la liste des lectures en echec (vide si le scan est complet).
function Find-SharedMailboxDelegations {
    param([Parameter(Mandatory)][object[]]$Items, [Parameter(Mandatory)][object[]]$SharedMailboxes)

    $byKey = @{}
    foreach ($it in $Items) { $byKey[$it.Key] = $it }
    $index    = New-TargetIdentityIndex $Items
    $failures = @()
    $sw       = [Diagnostics.Stopwatch]::StartNew()

    for ($i = 0; $i -lt $SharedMailboxes.Count; $i++) {
        $mb = $SharedMailboxes[$i]
        Write-ScanProgress 'BAL partagees' ($i + 1) $SharedMailboxes.Count $sw $mb.DisplayName
        $mbId = "$(Get-Prop $mb 'PrimarySmtpAddress')"
        if (-not $mbId) { $mbId = "$($mb.Identity)" }

        if ($SharedMailboxPermissionTypes -contains 'FullAccess') {
            try {
                foreach ($ace in @(Invoke-WithRetry { Get-EXOMailboxPermission -Identity $mbId -ErrorAction Stop -WarningAction SilentlyContinue })) {
                    if ((Get-Prop $ace 'IsInherited') -or (Get-Prop $ace 'Deny')) { continue }
                    if ((@(Get-Prop $ace 'AccessRights') -join ',') -notmatch 'FullAccess') { continue }
                    foreach ($k in @(Find-TargetKeys (Get-Prop $ace 'User') $index)) { Add-SharedMailboxDelegation $byKey[$k] $mb $mbId 'FullAccess' }
                }
            }
            catch { $failures += "$($mb.DisplayName) [FullAccess] : $($_.Exception.Message)" }
        }

        if ($SharedMailboxPermissionTypes -contains 'SendAs') {
            try {
                foreach ($ace in @(Invoke-WithRetry { Get-EXORecipientPermission -Identity $mbId -ErrorAction Stop -WarningAction SilentlyContinue })) {
                    if ((Get-Prop $ace 'IsInherited') -or "$(Get-Prop $ace 'AccessControlType')" -eq 'Deny') { continue }
                    if ((@(Get-Prop $ace 'AccessRights') -join ',') -notmatch 'SendAs') { continue }
                    foreach ($k in @(Find-TargetKeys (Get-Prop $ace 'Trustee') $index)) { Add-SharedMailboxDelegation $byKey[$k] $mb $mbId 'SendAs' }
                }
            }
            catch { $failures += "$($mb.DisplayName) [SendAs] : $($_.Exception.Message)" }
        }

        if ($SharedMailboxPermissionTypes -contains 'SendOnBehalf') {
            # GrantSendOnBehalfTo est deja porte par l'objet : aucun appel supplementaire.
            foreach ($d in @(Get-PropValues $mb 'GrantSendOnBehalfTo')) {
                foreach ($k in @(Find-TargetKeys $d $index)) { Add-SharedMailboxDelegation $byKey[$k] $mb $mbId 'SendOnBehalf' }
            }
        }
    }
    Write-Progress -Activity 'BAL partagees' -Completed

    foreach ($it in $Items) {
        $n = @($it.SharedMailboxPermissions).Count
        if ($n) {
            $it.SharedMailboxPermissions = @($it.SharedMailboxPermissions | Sort-Object MailboxDisplayName, PermissionType)
            $it.Anomalies += "[!] Delegation(s) sur $n BAL partagee(s)"
        }
    }
    return $failures
}

function Remove-SharedMailboxDelegation {
    param([Parameter(Mandatory)]$Permission, [Parameter(Mandatory)][string]$UserIdentity)
    switch ($Permission.PermissionType) {
        'FullAccess' {
            Remove-MailboxPermission -Identity $Permission.MailboxId -User $UserIdentity `
                -AccessRights FullAccess -InheritanceType All -Confirm:$false -ErrorAction Stop
        }
        'SendAs' {
            Remove-RecipientPermission -Identity $Permission.MailboxId -Trustee $UserIdentity `
                -AccessRights SendAs -Confirm:$false -ErrorAction Stop
        }
        'SendOnBehalf' {
            Set-Mailbox -Identity $Permission.MailboxId -GrantSendOnBehalfTo @{ Remove = $UserIdentity } -ErrorAction Stop
        }
        default { throw "Type non pris en charge : $($Permission.PermissionType)" }
    }
}

# ====================================================================
# LICENCES
# ====================================================================

# Texte de chaque feuille d'un .xlsx, lu directement dans l'archive OpenXML :
# ni Excel (COM) ni module ImportExcel requis. Autres extensions : texte brut.
function Get-WorkbookText {
    param([Parameter(Mandatory)][string]$Path)

    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($ext -eq '.xls') { throw 'Format .xls non pris en charge : enregistrer le fichier en .xlsx.' }
    if ($ext -ne '.xlsx') { return [pscustomobject]@{ Sheet = ''; Text = [IO.File]::ReadAllText($Path) } }

    Add-Type -AssemblyName System.IO.Compression
    # FileShare.ReadWrite : le classeur peut rester ouvert dans Excel.
    $stream = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    $zip    = $null
    try {
        $zip = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Read)
        $readXml = {
            param([string]$EntryName)
            $entry = $zip.GetEntry($EntryName)
            if (-not $entry) { return $null }
            $reader = New-Object IO.StreamReader($entry.Open())
            try { $xml = New-Object Xml.XmlDocument; $xml.LoadXml($reader.ReadToEnd()); return $xml }
            finally { $reader.Dispose() }
        }

        $shared = @()
        $sst = & $readXml 'xl/sharedStrings.xml'
        if ($sst) { $shared = @($sst.SelectNodes("//*[local-name()='si']") | ForEach-Object { $_.InnerText }) }

        $workbook = & $readXml 'xl/workbook.xml'
        $rels     = & $readXml 'xl/_rels/workbook.xml.rels'
        foreach ($sheet in @($workbook.SelectNodes("//*[local-name()='sheet']"))) {
            $relId  = @($sheet.Attributes | Where-Object { $_.LocalName -eq 'id' } | ForEach-Object { $_.Value }) | Select-Object -First 1
            $target = $rels.SelectSingleNode("//*[local-name()='Relationship'][@Id='$relId']").GetAttribute('Target')
            $data   = & $readXml $(if ($target.StartsWith('/')) { $target.TrimStart('/') } else { "xl/$target" })
            if (-not $data) { continue }

            $values = foreach ($cell in @($data.SelectNodes("//*[local-name()='c']"))) {
                $v = $cell.SelectSingleNode("*[local-name()='v']")
                switch ($cell.GetAttribute('t')) {
                    's'         { if ($v) { $shared[[int]$v.InnerText] } }
                    'inlineStr' { $cell.InnerText }
                    default     { if ($v) { $v.InnerText } }
                }
            }
            [pscustomobject]@{ Sheet = $sheet.GetAttribute('name'); Text = (@($values) -join "`n") }
        }
    }
    finally {
        if ($zip) { $zip.Dispose() }
        $stream.Dispose()
    }
}

# Adresse (minuscules) -> libelles "Editeur (feuille X)".
function New-LicenseIndex {
    param([object[]]$Files)
    $index = @{}
    foreach ($lf in @($Files)) {
        if (-not (Test-Path -LiteralPath $lf.Path -PathType Leaf)) { Write-Warning "[Licences] Fichier absent : $($lf.Path)"; continue }
        try { $sheets = @(Get-WorkbookText $lf.Path) }
        catch { Write-Warning "[Licences] Lecture impossible de $($lf.Path) : $($_.Exception.Message)"; continue }

        foreach ($s in $sheets) {
            $label = if ($s.Sheet) { "$($lf.Name) (feuille $($s.Sheet))" } else { $lf.Name }
            foreach ($m in $EmailRegex.Matches($s.Text)) {
                $k = $m.Value.ToLowerInvariant()
                if (-not $index.ContainsKey($k)) { $index[$k] = @() }
                if ($index[$k] -notcontains $label) { $index[$k] += $label }
            }
        }
    }
    return $index
}

# ====================================================================
# DECISIONS, EXECUTION
# ====================================================================

function Show-UserSummary {
    param([Parameter(Mandatory)]$Item)

    Write-Host "`n================ $($Item.UPN) ================" -ForegroundColor Cyan
    $ad = $Item.ADUser
    Write-Host ("[AD] {0} | Actif : {1} | {2} groupe(s)" -f $ad.SamAccountName, $ad.Enabled, @($Item.ADGroupDNs).Count)

    if ($Item.Mailbox) {
        Write-Host ("[Exchange] {0} | {1}" -f (Get-Prop $Item.Mailbox 'PrimarySmtpAddress'), (Get-Prop $Item.Mailbox 'RecipientTypeDetails'))
    }
    elseif ($Item.Recipient) { Write-Host "[Exchange] Pas de BAL - destinataire $(Get-Prop $Item.Recipient 'RecipientTypeDetails')" }

    if (@($Item.DLEntries).Count) {
        Write-Host ("[DL] {0} : {1}" -f @($Item.DLEntries).Count, (@($Item.DLEntries | ForEach-Object { $_.DisplayName }) -join ', '))
    }

    $idx = 0
    foreach ($p in @($Item.SharedMailboxPermissions)) {
        if ($idx -eq 0) { Write-Host '[BAL partagees]' -ForegroundColor Red }
        $idx++
        Write-Host ("  {0}. {1} <{2}> : {3}" -f $idx, $p.MailboxDisplayName, $p.MailboxId, $p.PermissionType) -ForegroundColor Red
    }

    foreach ($a in @($Item.Anomalies)) { Write-Host "  $a" -ForegroundColor Yellow }
}

function Select-SharedMailboxRemoval {
    param([Parameter(Mandatory)]$Item)
    $all = @($Item.SharedMailboxPermissions)
    $d = Read-Choice "Retirer les $($all.Count) delegation(s) BAL de $($Item.UPN) ? (O = toutes / N = aucune / D = au cas par cas)" 'O', 'N', 'D'
    $Item.SharedMailboxDecision = $d
    $Item.SharedMailboxPermissionsToRemove = @(switch ($d) {
        'O' { $all }
        'D' { $all | Where-Object { (Read-Choice ("  Retirer {0} sur {1} ? (O/N)" -f $_.PermissionType, $_.MailboxDisplayName)) -eq 'O' } }
    })
    if ($d -eq 'D') { $Item.SharedMailboxDecision = "Detail ($(@($Item.SharedMailboxPermissionsToRemove).Count)/$($all.Count))" }
}

# Une action d'offboarding : -WhatIf / -Confirm, reessais, journal. Ne leve jamais.
function Invoke-OffboardingStep {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)]$Item, [Parameter(Mandatory)][string]$Description, [Parameter(Mandatory)][scriptblock]$Action)
    if (-not $PSCmdlet.ShouldProcess($Item.UPN, $Description)) { $Item.Journal += "Simulation : $Description"; return }
    try {
        Invoke-WithRetry $Action | Out-Null
        $Item.Journal += "OK : $Description"
    }
    catch {
        $Item.Errors  += "$Description : $($_.Exception.Message)"
        $Item.Journal += "ERREUR : $Description"
    }
}

# Exchange d'abord, desactivation AD en dernier.
function Invoke-UserOffboarding {
    param([Parameter(Mandatory)]$User)
    $id = $User.ExchangeId
    $errorsBefore = @($User.Errors).Count

    # 1. Delegations BAL partagees (uniquement celles selectionnees)
    $toRemove = @($User.SharedMailboxPermissionsToRemove)
    foreach ($perm in $toRemove) {
        Invoke-OffboardingStep $User ("Retrait {0} sur BAL '{1}'" -f $perm.PermissionType, $perm.MailboxDisplayName) {
            Remove-SharedMailboxDelegation $perm $id
        }
    }
    foreach ($perm in @($User.SharedMailboxPermissions | Where-Object { $toRemove -notcontains $_ })) {
        $User.Journal += "Conservee : $($perm.PermissionType) sur BAL '$($perm.MailboxDisplayName)'"
    }

    # 2. Listes de distribution
    foreach ($dl in @($User.DLEntries)) {
        if (Get-Prop $dl 'IsDirSynced') {
            # Non modifiable dans Exchange Online : traitee par le retrait du groupe AD.
            $User.Journal += "DL '$($dl.DisplayName)' synchronisee depuis AD : retiree via les groupes AD"
            continue
        }
        $dlId = "$(Get-Prop $dl 'PrimarySmtpAddress')"
        if (-not $dlId) { $dlId = "$($dl.Identity)" }
        Invoke-OffboardingStep $User "Retrait DL '$($dl.DisplayName)'" {
            Remove-DistributionGroupMember -Identity $dlId -Member $id -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction Stop
        }
    }

    # 3. Groupes AD (hors groupes proteges)
    foreach ($dn in @($User.ADGroupDNs)) {
        $name = Get-NameFromDN $dn
        if (Test-IsProtectedGroupDN $dn) { $User.Journal += "Groupe protege conserve : $name"; continue }
        Invoke-OffboardingStep $User "Retrait groupe AD '$name'" {
            Remove-ADGroupMember -Identity $dn -Members $User.ADUser -Confirm:$false -ErrorAction Stop
        }
    }

    # 4. Desactivation, en dernier
    if (@($User.Errors).Count -gt $errorsBefore -and -not $DisableAccountOnPartialFailure) {
        $User.Journal += 'Desactivation AD reportee : corriger les erreurs puis relancer le script'
    }
    else {
        Invoke-OffboardingStep $User 'Desactivation du compte AD' {
            Disable-ADAccount -Identity $User.ADUser -ErrorAction Stop
        }
    }

    $User.StatutExecution = if (@($User.Errors).Count -gt $errorsBefore) { 'Partiel' }
                            elseif ($WhatIfPreference) { 'Simulation' }
                            else { 'Execute' }
}

# ====================================================================
# EXPORT
# ====================================================================

function ConvertTo-ExportRow {
    param([Parameter(Mandatory)]$Item)
    $perms  = @($Item.SharedMailboxPermissions)
    $byType = {
        param([string]$Type)
        Join-Values @($perms | Where-Object { $_.PermissionType -eq $Type } | ForEach-Object { "$($_.MailboxDisplayName) <$($_.MailboxId)>" })
    }

    [pscustomobject]@{
        Date                      = $Item.DateDecision
        UPN                       = $Item.UPN
        CompteAD                  = "$(Get-Prop $Item.ADUser 'SamAccountName')"
        EnabledAD                 = "$(Get-Prop $Item.ADUser 'Enabled')"
        MailboxTrouvee            = $(if ($Item.Mailbox) { 'Oui' } else { 'Non' })
        PrimarySMTP               = "$(Get-Prop $Item.Recipient 'PrimarySmtpAddress')"
        NbGroupesAD               = @($Item.ADGroupDNs).Count
        GroupesAD                 = Join-Values @($Item.ADGroupDNs | ForEach-Object { Get-NameFromDN $_ })
        NbDL                      = @($Item.DLEntries).Count
        DLExchange                = Join-Values @($Item.DLEntries | ForEach-Object { $_.DisplayName })
        MembreBALPartagee         = $(if ($perms.Count) { 'Oui' } else { 'Non' })
        NbDelegationsBALPartagees = $perms.Count
        BALFullAccess             = & $byType 'FullAccess'
        BALSendAs                 = & $byType 'SendAs'
        BALSendOnBehalf           = & $byType 'SendOnBehalf'
        DecisionRetraitBAL        = $Item.SharedMailboxDecision
        NbBALSelectionnees        = @($Item.SharedMailboxPermissionsToRemove).Count
        EstMembrePowerPDF         = $(if ($Item.IsMemberOfPowerPDFGroup) { 'Oui' } else { 'Non' })
        Licences                  = Join-Values $Item.Licenses
        Anomalies                 = Join-Values $Item.Anomalies
        ReglesInbox               = Join-Values $Item.InboxRuleFindings
        DecisionAnomalies         = $Item.DecisionAnomalies
        DecisionGlobale           = $Item.DecisionGlobale
        StatutExecution           = $Item.StatutExecution
        Journal                   = (@($Item.Journal) -join ' | ')
        Erreurs                   = Join-Values $Item.Errors
    }
}

function Write-ExportCsv {
    param([object[]]$Items, [string]$Path)
    try {
        $rows = @($Items | ForEach-Object { ConvertTo-ExportRow $_ })
        if (-not $rows.Count) { Write-Warning 'Aucune ligne a exporter.'; return }
        # -WhatIf:$false : sinon -WhatIf sur le script supprimait aussi le rapport.
        $rows | Export-Csv -LiteralPath $Path -Delimiter ';' -NoTypeInformation -Encoding UTF8 -WhatIf:$false
        Write-Host "[CSV] $Path" -ForegroundColor Green
    }
    catch { Write-Warning "Export CSV impossible : $($_.Exception.Message)" }
}

# ====================================================================
# TRAITEMENT
# ====================================================================
$items            = @()
$exportCsvPath    = $null
$exoConnectedHere = $false

try {
    foreach ($mod in 'ActiveDirectory', 'ExchangeOnlineManagement') {
        if (-not (Get-Module -ListAvailable -Name $mod)) { throw "Module $mod absent." }
    }
    Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue

    New-Item -Path $ExportRoot -ItemType Directory -Force -WhatIf:$false | Out-Null
    $exportCsvPath = Join-Path $ExportRoot ('Export_Offboarding_Audit_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

    $upnList = @(Get-RequestedUpns -Values $UserPrincipalName -Path $InputFile)
    if (-not $upnList.Count) { Write-Warning 'Aucun UPN valide.'; return }
    $items = @($upnList | ForEach-Object { New-WorkItem $_ })

    # ---------------- 1. ACTIVE DIRECTORY ---------------------------
    Resolve-ADAccounts $items
    $adItems = @($items | Where-Object { $_.ADUser })
    Write-Host ("[1/5] Active Directory : {0}/{1} compte(s) trouve(s)" -f $adItems.Count, $items.Count) -ForegroundColor Yellow
    foreach ($it in @($items | Where-Object { -not $_.ADUser })) { Write-Host "      Introuvable : $($it.UPN)" -ForegroundColor Red }

    if ($adItems.Count) {
        try {
            $targetGroupDN = (Get-ADGroup -Identity $TargetSecurityGroupName -ErrorAction Stop).DistinguishedName
            foreach ($it in $adItems) {
                if ($it.ADGroupDNs -contains $targetGroupDN) {
                    $it.IsMemberOfPowerPDFGroup = $true
                    $it.Anomalies += "[!] Membre de $TargetSecurityGroupName"
                }
            }
        }
        catch { Write-Warning "Groupe cible absent : $TargetSecurityGroupName" }

        # ---------------- 2. EXCHANGE -------------------------------
        # Connexion seulement maintenant : inutile si aucun utilisateur n'est concerne.
        Import-Module ExchangeOnlineManagement -ErrorAction Stop -WarningAction SilentlyContinue
        $connected = $false
        if (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue) {
            try { $connected = [bool]@(Get-ConnectionInformation | Where-Object { "$($_.State)" -eq 'Connected' }).Count } catch { $connected = $false }
        }
        if (-not $connected) {
            try { Connect-ExchangeOnline -ShowBanner:$false | Out-Null; $exoConnectedHere = $true }
            catch { throw "Connexion Exchange Online impossible : $($_.Exception.Message)" }
        }

        Resolve-ExchangeRecipients $adItems
        $exoItems = @($adItems | Where-Object { $_.Recipient })
        Write-Host ("[2/5] Exchange : {0} destinataire(s), dont {1} boite(s) aux lettres" -f $exoItems.Count, @($exoItems | Where-Object { $_.Mailbox }).Count) -ForegroundColor Yellow

        # ---------------- 3. LISTES DE DISTRIBUTION -----------------
        if ($exoItems.Count) {
            Find-UserDistributionGroups $exoItems
            $nbDL = 0; foreach ($it in $exoItems) { $nbDL += @($it.DLEntries).Count }
            Write-Host "[3/5] Listes de distribution : $nbDL appartenance(s)" -ForegroundColor Yellow
        }
        else { Write-Host '[3/5] Listes de distribution : aucun utilisateur concerne, ignore' -ForegroundColor Gray }

        # ---------------- 4. BAL PARTAGEES --------------------------
        if (-not $ScanSharedMailboxPermissions) { Write-Host '[4/5] BAL partagees : desactive' -ForegroundColor Gray }
        elseif (-not $exoItems.Count) { Write-Host '[4/5] BAL partagees : aucun utilisateur concerne, ignore' -ForegroundColor Gray }
        else {
            try {
                $shared = @(Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited `
                            -Properties GrantSendOnBehalfTo -ErrorAction Stop -WarningAction SilentlyContinue)
                Write-Host "[4/5] BAL partagees : analyse silencieuse de $($shared.Count) BAL..." -ForegroundColor Yellow
                $failures = @(Find-SharedMailboxDelegations -Items $exoItems -SharedMailboxes $shared)

                $concernes = @($exoItems | Where-Object { @($_.SharedMailboxPermissions).Count })
                if ($concernes.Count) { Write-Host "      $($concernes.Count) utilisateur(s) delegue(s) sur au moins une BAL partagee" -ForegroundColor Red }
                else { Write-Host '      Aucune delegation pour les utilisateurs demandes' -ForegroundColor Green }

                if ($failures.Count) {
                    Write-Warning ("{0} lecture(s) de BAL en echec, resultat possiblement incomplet : {1}" -f $failures.Count, (@($failures | Select-Object -First 5) -join ' ; '))
                    $failures | ForEach-Object { Write-Verbose $_ }
                }
            }
            catch { Write-Warning "Analyse BAL partagees impossible : $($_.Exception.Message)" }
        }
    }

    # ---------------- 5. LICENCES -----------------------------------
    $licenseIndex = New-LicenseIndex $LicenseFiles
    $nbLic = 0
    foreach ($it in $items) {
        $it.Licenses = @($it.Addresses | Where-Object { $licenseIndex.ContainsKey($_) } | ForEach-Object { $licenseIndex[$_] } | Sort-Object -Unique)
        if ($it.Licenses.Count) {
            $nbLic++
            if ($it.ADUser) { $it.Anomalies += '[!] Licence(s) : ' + ($it.Licenses -join ', ') }
        }
    }
    Write-Host "[5/5] Licences : $nbLic utilisateur(s) concerne(s)" -ForegroundColor Yellow

    # ---------------- REVUE : seulement les utilisateurs concernes ---
    # La liste numerotee des BAL est affichee une seule fois, dans le resume.
    $ready = @()
    foreach ($it in $adItems) {
        if (@($it.Anomalies).Count) {
            Show-UserSummary $it
            $it.DecisionAnomalies = Read-Choice "Continuer pour $($it.UPN) malgre les anomalies ? (O/N)"
            $it.DateDecision      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            if ($it.DecisionAnomalies -ne 'O') { $it.StatutExecution = 'Bloque apres analyse des anomalies'; continue }
        }
        if (@($it.SharedMailboxPermissions).Count) { Select-SharedMailboxRemoval $it }
        $ready += $it
    }

    # ---------------- RESUME ET CONFIRMATION UNIQUE -----------------
    Write-Host "`n================ RESUME GLOBAL ================" -ForegroundColor Cyan
    Write-Host ("Total : {0} | Prets : {1} | Bloques : {2} | Introuvables AD : {3}" -f
        $items.Count, $ready.Count, ($adItems.Count - $ready.Count), ($items.Count - $adItems.Count))

    $decision = 'N'
    if ($ready.Count) {
        $plan = @($ready | ForEach-Object {
            [pscustomobject]@{
                UPN       = $_.UPN
                GroupesAD = @($_.ADGroupDNs | Where-Object { -not (Test-IsProtectedGroupDN $_) }).Count
                DL        = @($_.DLEntries | Where-Object { -not (Get-Prop $_ 'IsDirSynced') }).Count
                BAL       = '{0}/{1}' -f @($_.SharedMailboxPermissionsToRemove).Count, @($_.SharedMailboxPermissions).Count
            }
        })
        $plan | Format-Table -AutoSize | Out-Host
        $mode = if ($WhatIfPreference) { ' (SIMULATION -WhatIf)' } else { '' }
        $decision = Read-Choice "Retirer groupes, DL et delegations puis desactiver les $($ready.Count) compte(s)$mode ? (O/N)"
    }

    $now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    foreach ($it in $ready) {
        $it.DecisionGlobale = $decision
        if (-not $it.DateDecision) { $it.DateDecision = $now }
    }
    Write-ExportCsv $items $exportCsvPath
    if ($decision -ne 'O') { Write-Host '[STOP] Aucune modification.' -ForegroundColor Yellow; return }

    # ---------------- EXECUTION -------------------------------------
    foreach ($w in $ready) {
        Invoke-UserOffboarding $w
        $color = switch ($w.StatutExecution) { 'Execute' { 'Green' } 'Simulation' { 'Gray' } default { 'Red' } }
        Write-Host ("[{0}] {1}" -f $w.StatutExecution, $w.UPN) -ForegroundColor $color
        foreach ($e in @($w.Errors)) { Write-Host "      $e" -ForegroundColor Red }
    }

    Write-ExportCsv $items $exportCsvPath
    Write-Host "`n[OK] Traitement termine. Rapport : $exportCsvPath" -ForegroundColor Cyan
}
catch {
    # Pas de Write-Error ici : avec $ErrorActionPreference = 'Stop' il levait
    # immediatement et l'export de secours n'etait jamais ecrit.
    Write-Host "Erreur fatale : $($_.Exception.Message)" -ForegroundColor Red
    if ($exportCsvPath -and $items.Count) { Write-ExportCsv $items $exportCsvPath }
    throw
}
finally {
    if ($exoConnectedHere) { try { Disconnect-ExchangeOnline -Confirm:$false -WhatIf:$false | Out-Null } catch {} }
}
