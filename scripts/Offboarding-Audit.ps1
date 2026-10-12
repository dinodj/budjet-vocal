#requires -Version 5.1

<#
.SYNOPSIS
    Audit et offboarding : comptes AD, boites aux lettres (dont mise en litige),
    listes de distribution, delegations, licences Microsoft 365 et applicatives.

.DESCRIPTION
    Version 5.2 - analyses CIBLEES, VISIBLES et ACCELEREES :
      - seuls les UPN trouves dans AD sont analyses dans Exchange, et seuls
        ceux qui ont un objet Exchange sont recherches dans les DL et les
        delegations. Si aucun utilisateur n'est concerne, le scan est saute (la
        connexion Exchange Online elle-meme n'est ouverte que si necessaire) ;
      - DL, SendAs et SendOnBehalf : un appel serveur par utilisateur
        (Members -eq <DN>, Get-RecipientPermission -Trustee,
        GrantSendOnBehalfTo -eq <DN>), quel que soit le nombre de boites ;
      - FullAccess : un appel par boite (aucune recherche inverse n'existe),
        accelere par un cache local et par le choix automatique de la cmdlet
        la plus rapide. Les boites ou un utilisateur est trouve sont toujours
        relues en direct ;
      - les boites aux lettres accessibles sont listees par utilisateur ;
      - ALERTE si la boite de l'utilisateur est en litige (Litigation Hold),
        et etiquette [LITIGE] sur les boites accessibles concernees ;
      - licences Microsoft 365 (Microsoft Graph, avec le groupe qui les
        attribue) et licences applicatives avec leur type (colonnes des
        fichiers Excel : produit, type de licence...).

    Ordre d'execution : delegations, DL, groupes AD, puis desactivation.
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

.PARAMETER Silent
    Masque les barres de progression (affichees par defaut).

.PARAMETER RefreshCache
    Ignore le cache FullAccess et relit toutes les boites (et refait le calibrage).

.EXAMPLE
    .\Offboarding-Audit.ps1 -InputFile C:\Temp\departs.csv -WhatIf

.NOTES
    Version    : 5.2
    Prerequis  : ActiveDirectory, ExchangeOnlineManagement v2+
                 Microsoft.Graph.Authentication (facultatif, licences Microsoft 365)
    Compatible : Windows PowerShell 5.1
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string[]]$UserPrincipalName,
    [string]$InputFile,
    [string]$ExportRoot = 'C:\Temp\AD\Logs\AD+DL',
    [switch]$Silent,
    [switch]$RefreshCache
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ($Silent) { $ProgressPreference = 'SilentlyContinue' }

# ====================================================================
# CONFIGURATION
# ====================================================================
$ScanInboxRules                 = $true
$ScanMailboxDelegations         = $true
$DelegationTypes                = @('FullAccess', 'SendAs', 'SendOnBehalf')
$DisableAccountOnPartialFailure = $false

# FullAccess exige un appel par boite : ajouter 'RoomMailbox', 'EquipmentMailbox'
# ou 'UserMailbox' elargit la recherche mais allonge d'autant la premiere analyse.
# (SendAs et SendOnBehalf couvrent deja tous les types de boites.)
$FullAccessMailboxTypes         = @('SharedMailbox')
$FullAccessCmdlet               = 'Auto'   # ou 'Get-EXOMailboxPermission' / 'Get-MailboxPermission'
$FullAccessCacheHours           = 24       # 0 = pas de cache ; -RefreshCache force une relecture

$ADChunkSize                    = 100
$BulkMailboxThreshold           = 300   # au-dela, un seul Get-EXOMailbox pour tout le tenant

$MaxRetries                     = 3
$RetryBaseDelayMs               = 2000

# Licences Microsoft 365 via Microsoft Graph (module Microsoft.Graph.Authentication).
# GroupMember.Read.All sert seulement a nommer le groupe qui attribue une licence.
$ShowM365Licenses               = $true
$GraphScopes                    = @('User.Read.All', 'GroupMember.Read.All')
$LicenseNamesCsvUrl             = 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv'
# Colonnes des fichiers de licences applicatives decrivant le type de licence.
$LicenseTypeColumnPattern       = 'licen|produit|product|logiciel|software|offre|abonnement|subscription|edition|type|plan'

$TargetSecurityGroupName        = 'GrpSecu-Utilisateurs_POWERPDF'
$FullAccessCachePath            = Join-Path $ExportRoot 'Cache_FullAccess.clixml'
$script:FullAccessCache         = $null
$script:GraphConnectedHere      = $false

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
$MailboxProperties   = @('LitigationHoldEnabled', 'LitigationHoldDate', 'LitigationHoldOwner', 'LitigationHoldDuration',
                         'InPlaceHolds', 'ForwardingAddress', 'ForwardingSmtpAddress', 'DeliverToMailboxAndForward')

$UpnPattern          = '^[^@\s]+@[^@\s]+\.[^@\s]+$'
$EmailRegex          = [regex]'[\w.+-]+@[\w-]+(?:\.[\w-]+)+'

# Erreurs definitives : inutile de reessayer (un UPN absent coutait 12 s).
$NonRetryablePattern = "couldn't be found|could not be found|can't be found|cannot find|not found|" +
                       "impossible de trouver|introuvable|n'existe pas|isn't a member|is not a member|" +
                       "n'est pas membre|already|existe d.j.|synchroni[sz]|access ?denied|acc.s refus.|" +
                       "sufficient permission|insufficient|droits? insuffisants|unauthorized|non autoris|" +
                       "does not exist|forbidden|\b40[34]\b|" +
                       "isn't valid|n'est pas valide|cannot bind|impossible de lier"

# ====================================================================
# UTILITAIRES
# ====================================================================

# Acces sur a une propriete : indispensable sous Set-StrictMode 2.0, les objets
# Exchange n'exposant pas les memes proprietes selon le RecipientTypeDetails.
function Get-Prop {
    param($InputObject, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject[$Name] }
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

# Write-Progress est couteux sous Windows PowerShell 5.1 : 4 rafraichissements
# par seconde au plus, sinon l'affichage ralentit lui-meme l'analyse.
$script:ProgressClock  = [Diagnostics.Stopwatch]::StartNew()
$script:LastProgressMs = -1000
function Write-ScanProgress {
    param([string]$Activity, [int]$Current, [int]$Total, [Diagnostics.Stopwatch]$Stopwatch, [string]$CurrentItem = '')
    if ($ProgressPreference -eq 'SilentlyContinue' -or $Total -le 0) { return }
    $now = $script:ProgressClock.ElapsedMilliseconds
    if ($Current -gt 1 -and $Current -lt $Total -and $now - $script:LastProgressMs -lt 250) { return }
    $script:LastProgressMs = $now
    $status = "$Current / $Total"
    # $Current est l'element en cours : $Current - 1 sont termines.
    if ($Current -gt 1 -and $Current -lt $Total) {
        $remaining = [int][math]::Floor($Stopwatch.Elapsed.TotalSeconds / ($Current - 1) * ($Total - $Current + 1))
        $status += ' - ETA {0:00}:{1:00}' -f [math]::Floor($remaining / 60), ($remaining % 60)
    }
    if ($CurrentItem) { $status += " - $CurrentItem" }
    Write-Progress -Activity $Activity -Status $status -PercentComplete ([math]::Min(100, $Current * 100 / $Total))
}

function Format-Duration {
    param([TimeSpan]$Elapsed)
    return '{0:00}:{1:00}' -f [math]::Floor($Elapsed.TotalMinutes), $Elapsed.Seconds
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
        Delegations                      = @()
        DelegationsToRemove              = @()
        DelegationDecision               = ''
        LitigationHold                   = ''         # detail de la mise en litige, vide sinon
        AppLicenses                      = @()
        M365Licenses                     = @()
        M365Checked                      = $false
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

function Format-LitigationHold {
    param([Parameter(Mandatory)]$Mailbox)
    $parts = @()
    $date = Get-Prop $Mailbox 'LitigationHoldDate'
    if ($date) { $parts += 'depuis le ' + $(if ($date -is [datetime]) { $date.ToString('yyyy-MM-dd') } else { "$date" }) }
    $owner = "$(Get-Prop $Mailbox 'LitigationHoldOwner')"
    if ($owner) { $parts += "par $owner" }
    $duration = "$(Get-Prop $Mailbox 'LitigationHoldDuration')"
    if ($duration) {
        $ts = [TimeSpan]::Zero
        $parts += $(if ($duration -match 'unlimited') { 'duree illimitee' }
                    elseif ([TimeSpan]::TryParse($duration, [ref]$ts)) { "duree $([int]$ts.TotalDays) jours" }
                    else { "duree $duration" })
    }
    return (@('actif') + $parts) -join ', '
}

function Show-LitigationAlert {
    param([Parameter(Mandatory)][object[]]$Items)
    Write-Host "`n################### ALERTE : MISE EN LITIGE ###################" -ForegroundColor Red
    foreach ($it in $Items) { Write-Host "  $($it.UPN) : Litigation Hold $($it.LitigationHold)" -ForegroundColor Red }
    Write-Host '  -> Boite sous conservation legale : prevenir le juridique / la conformite' -ForegroundColor Red
    Write-Host '     avant toute suppression du compte, de la boite ou de sa licence.' -ForegroundColor Red
    Write-Host "###############################################################" -ForegroundColor Red
}

function Add-MailboxAnomalies {
    param([Parameter(Mandatory)]$Item)
    $m = $Item.Mailbox

    if (Get-Prop $m 'LitigationHoldEnabled') {
        $Item.LitigationHold = Format-LitigationHold $m
        $Item.Anomalies     += "[!] MISE EN LITIGE : Litigation Hold $($Item.LitigationHold)"
    }
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
# DELEGATIONS SUR LES BOITES AUX LETTRES
# ====================================================================
#   - SendAs       : Get-RecipientPermission -Trustee, UN appel par utilisateur ;
#   - SendOnBehalf : filtre serveur GrantSendOnBehalfTo -eq <DN>, UN appel par utilisateur ;
#   - FullAccess   : pas de recherche inverse cote Exchange, donc un appel par
#                    boite, accelere par un cache local et par le choix
#                    automatique de la cmdlet la plus rapide sur le tenant.

<#
    Index inverse des identites des SEULS utilisateurs traites : cle normalisee
    -> cles des work items, pour reconnaitre le champ User d'une ACE FullAccess
    (UPN, SMTP, DOMAINE\sam, Name, DN...). DisplayName est exclu : non unique,
    il produisait des faux positifs.
#>
function New-TargetIdentityIndex {
    param([Parameter(Mandatory)][object[]]$Items)
    $index = @{}
    foreach ($it in $Items) {
        $raw = @($it.UPN) + @($it.Addresses) + @(Get-Prop $it.ADUser 'SamAccountName')
        foreach ($p in 'UserPrincipalName', 'Alias', 'Name', 'Identity', 'Id', 'DistinguishedName', 'Guid', 'ExternalDirectoryObjectId') {
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

# Reference d'affichage et de retrait d'une boite (ou de tout destinataire).
function ConvertTo-MailboxRef {
    param($Recipient)
    $id = "$(Get-Prop $Recipient 'PrimarySmtpAddress')"
    if (-not $id) { $id = "$(Get-Prop $Recipient 'Identity')" }
    [pscustomobject]@{
        MailboxId      = $id
        DisplayName    = "$(Get-Prop $Recipient 'DisplayName')"
        Type           = "$(Get-Prop $Recipient 'RecipientTypeDetails')"
        LitigationHold = [bool](Get-Prop $Recipient 'LitigationHoldEnabled')
    }
}

function Format-MailboxLabel {
    param([Parameter(Mandatory)]$Delegation)
    $label = "$($Delegation.MailboxDisplayName) <$($Delegation.MailboxId)>"
    if ($Delegation.MailboxType) { $label += " [$($Delegation.MailboxType)]" }
    if ($Delegation.MailboxLitigationHold) { $label += ' [LITIGE]' }
    return $label
}

function Add-Delegation {
    param([Parameter(Mandatory)]$Item, [Parameter(Mandatory)]$Mailbox, [Parameter(Mandatory)][string]$Type, [string]$CacheKey = '')
    if (-not $Mailbox.MailboxId -or $Mailbox.MailboxId -eq $Item.ExchangeId) { return }   # sa propre boite
    if (@($Item.Delegations | Where-Object { $_.MailboxId -eq $Mailbox.MailboxId -and $_.PermissionType -eq $Type }).Count) { return }
    $Item.Delegations += [pscustomobject]@{
        MailboxId          = $Mailbox.MailboxId
        MailboxDisplayName = $Mailbox.DisplayName
        MailboxType        = $Mailbox.Type
        MailboxLitigationHold = [bool](Get-Prop $Mailbox 'LitigationHold')
        PermissionType     = $Type
        CacheKey           = $CacheKey
    }
}

# Identite renvoyee par Get-RecipientPermission (souvent le Name) -> reference.
# $Lookup memorise les resolutions : un seul Get-Recipient par destinataire.
function Resolve-RecipientRef {
    param([string]$Identity, [Parameter(Mandatory)][hashtable]$Lookup)
    $k = ConvertTo-IdentityKey $Identity
    if (-not $k) { return $null }   # une identite vide renverrait TOUS les destinataires
    if (-not $Lookup.ContainsKey($k)) {
        try { $Lookup[$k] = ConvertTo-MailboxRef (@(Invoke-WithRetry { Get-Recipient -Identity $Identity -ErrorAction Stop -WarningAction SilentlyContinue })[0]) }
        catch { $Lookup[$k] = [pscustomobject]@{ MailboxId = $Identity; DisplayName = $Identity; Type = ''; LitigationHold = $false } }
    }
    return $Lookup[$k]
}

function Find-SendAsDelegations {
    param([Parameter(Mandatory)][object[]]$Items, [Parameter(Mandatory)][hashtable]$Lookup)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $it = $Items[$i]
        Write-ScanProgress 'SendAs' ($i + 1) $Items.Count $sw $it.UPN
        try {
            foreach ($ace in @(Invoke-WithRetry { Get-RecipientPermission -Trustee $it.ExchangeId -ResultSize Unlimited -ErrorAction Stop -WarningAction SilentlyContinue })) {
                if ((Get-Prop $ace 'IsInherited') -or "$(Get-Prop $ace 'AccessControlType')" -eq 'Deny') { continue }
                if ((@(Get-Prop $ace 'AccessRights') -join ',') -notmatch 'SendAs') { continue }
                $ref = Resolve-RecipientRef "$(Get-Prop $ace 'Identity')" $Lookup
                if ($ref) { Add-Delegation $it $ref 'SendAs' }
            }
        }
        catch { $it.Anomalies += "[!] Lecture SendAs impossible : $($_.Exception.Message)" }
    }
    Write-Progress -Activity 'SendAs' -Completed
}

function Find-SendOnBehalfDelegations {
    param([Parameter(Mandatory)][object[]]$Items)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $it = $Items[$i]
        Write-ScanProgress 'SendOnBehalf' ($i + 1) $Items.Count $sw $it.UPN
        $dn = "$(Get-Prop $it.Recipient 'DistinguishedName')"
        if (-not $dn) { continue }   # deja signale par la phase DL
        $filter = "GrantSendOnBehalfTo -eq '{0}'" -f ($dn -replace "'", "''")
        try {
            foreach ($mb in @(Invoke-WithRetry { Get-Mailbox -Filter $filter -ResultSize Unlimited -ErrorAction Stop -WarningAction SilentlyContinue })) {
                Add-Delegation $it (ConvertTo-MailboxRef $mb) 'SendOnBehalf'
            }
        }
        catch { $it.Anomalies += "[!] Lecture SendOnBehalf impossible : $($_.Exception.Message)" }
    }
    Write-Progress -Activity 'SendOnBehalf' -Completed
}

# ---------- FullAccess : cache local -------------------------------

function Get-MailboxCacheKey {
    param([Parameter(Mandatory)]$Mailbox)
    foreach ($p in 'ExternalDirectoryObjectId', 'Guid', 'PrimarySmtpAddress') {
        $v = "$(Get-Prop $Mailbox $p)"
        if ($v) { return $v.ToLowerInvariant() }
    }
    return "$(Get-Prop $Mailbox 'DisplayName')".ToLowerInvariant()
}

function Import-FullAccessCache {
    $empty = @{ Version = 1; Cmdlet = ''; Mailboxes = @{} }
    if ($FullAccessCacheHours -le 0 -or $RefreshCache -or -not (Test-Path -LiteralPath $FullAccessCachePath)) { return $empty }
    try {
        $c = Import-Clixml -LiteralPath $FullAccessCachePath
        if ($c -is [hashtable] -and $c['Version'] -eq 1 -and $c['Mailboxes'] -is [hashtable]) { return $c }
    }
    catch { Write-Warning "Cache FullAccess illisible, reconstruction : $($_.Exception.Message)" }
    return $empty
}

function Save-FullAccessCache {
    if ($FullAccessCacheHours -le 0 -or $null -eq $script:FullAccessCache) { return }
    try { Export-Clixml -InputObject $script:FullAccessCache -LiteralPath $FullAccessCachePath -WhatIf:$false }
    catch { Write-Warning "Cache FullAccess non enregistre : $($_.Exception.Message)" }
}

function Get-FullAccessAce {
    param([Parameter(Mandatory)][string]$Cmdlet, [string]$Identity)
    # Une identite vide renverrait les permissions de TOUTES les boites.
    if ([string]::IsNullOrWhiteSpace($Identity)) { throw 'Identite de boite vide.' }
    if ($Cmdlet -eq 'Get-MailboxPermission') { Get-MailboxPermission -Identity $Identity -ErrorAction Stop -WarningAction SilentlyContinue }
    else { Get-EXOMailboxPermission -Identity $Identity -ErrorAction Stop -WarningAction SilentlyContinue }
}

# Lit les ACE FullAccess explicites des boites indiquees et met le cache a jour.
# Sans cmdlet imposee, les 6 premieres boites alternent les deux cmdlets et la
# plus rapide (mediane) est retenue pour la suite, puis memorisee dans le cache.
function Update-FullAccessCache {
    param([object[]]$Mailboxes)
    $failures = @()
    if (-not @($Mailboxes).Count) { return }
    $cache   = $script:FullAccessCache
    $cmdlets = @('Get-EXOMailboxPermission', 'Get-MailboxPermission')
    $chosen  = if ($FullAccessCmdlet -ne 'Auto') { $FullAccessCmdlet }
               elseif ($cache.Cmdlet) { $cache.Cmdlet }
               elseif ($Mailboxes.Count -lt 20) { $cmdlets[0] }
               else { '' }
    $timings = @{ $cmdlets[0] = @(); $cmdlets[1] = @() }
    $sw      = [Diagnostics.Stopwatch]::StartNew()

    for ($i = 0; $i -lt $Mailboxes.Count; $i++) {
        $mb = $Mailboxes[$i]
        Write-ScanProgress 'FullAccess' ($i + 1) $Mailboxes.Count $sw $mb.DisplayName
        $mbId = "$(Get-Prop $mb 'UserPrincipalName')"   # identite la plus rapide selon la doc Microsoft
        if (-not $mbId) { $mbId = "$(Get-Prop $mb 'PrimarySmtpAddress')" }

        $order = if ($chosen) { @($chosen) } elseif ($i % 2) { @($cmdlets[1], $cmdlets[0]) } else { $cmdlets }
        $aces = $null; $lastError = ''
        foreach ($cmd in $order) {
            $t = [Diagnostics.Stopwatch]::StartNew()
            try { $aces = @(Invoke-WithRetry { Get-FullAccessAce $cmd $mbId }); $timings[$cmd] += $t.Elapsed.TotalSeconds; break }
            catch { $timings[$cmd] += 1e6; $lastError = $_.Exception.Message }
        }
        if ($null -eq $aces) { $failures += "$($mb.DisplayName) : $lastError"; continue }

        $cache.Mailboxes[(Get-MailboxCacheKey $mb)] = [pscustomobject]@{
            ScannedUtc  = (Get-Date).ToUniversalTime()
            Users       = @($aces | Where-Object {
                                -not (Get-Prop $_ 'IsInherited') -and -not (Get-Prop $_ 'Deny') -and
                                (@(Get-Prop $_ 'AccessRights') -join ',') -match 'FullAccess' } |
                            ForEach-Object { "$(Get-Prop $_ 'User')" } |
                            Where-Object { $_ -and $_ -notmatch '^NT AUTHORITY\\|^S-1-5-' })
        }

        if (-not $chosen -and $i -ge 5) {
            $median = @{}
            foreach ($c in $cmdlets) { $v = @($timings[$c] | Sort-Object); $median[$c] = $v[[int][math]::Floor($v.Count / 2)] }
            $chosen = if ($median[$cmdlets[1]] -lt $median[$cmdlets[0]]) { $cmdlets[1] } else { $cmdlets[0] }
            $other  = @($cmdlets | Where-Object { $_ -ne $chosen })[0]
            $cache.Cmdlet = $chosen
            $detail = if ($median[$other] -ge 1e5) { "$other en echec" } else { '{0:N2} s/boite contre {1:N2} s pour {2}' -f $median[$chosen], $median[$other], $other }
            Write-Host "      FullAccess : $chosen retenue ($detail)" -ForegroundColor Gray
        }
    }
    Write-Progress -Activity 'FullAccess' -Completed
    return $failures
}

function Get-FullAccessHits {
    param([Parameter(Mandatory)][hashtable]$Index)
    $entries = $script:FullAccessCache.Mailboxes
    foreach ($key in @($entries.Keys)) {
        foreach ($u in @($entries[$key].Users)) {
            foreach ($k in @(Find-TargetKeys $u $Index)) { [pscustomobject]@{ CacheKey = $key; ItemKey = $k } }
        }
    }
}

# Renvoie la liste des boites illisibles (vide si l'analyse est complete).
function Find-FullAccessDelegations {
    param([Parameter(Mandatory)][object[]]$Items, [Parameter(Mandatory)][hashtable]$ByKey, [Parameter(Mandatory)][hashtable]$Lookup)

    $script:FullAccessCache = Import-FullAccessCache
    $entries = $script:FullAccessCache.Mailboxes
    try {
        $mailboxes = @(Get-EXOMailbox -RecipientTypeDetails $FullAccessMailboxTypes -ResultSize Unlimited -Properties LitigationHoldEnabled, WhenChangedUTC -ErrorAction Stop -WarningAction SilentlyContinue)
    }
    catch {
        # WhenChangedUTC indisponible : le cache ne se fie alors qu'a son age.
        $mailboxes = @(Get-EXOMailbox -RecipientTypeDetails $FullAccessMailboxTypes -ResultSize Unlimited -Properties LitigationHoldEnabled -ErrorAction Stop -WarningAction SilentlyContinue)
    }

    # A relire : boites absentes du cache, modifiees depuis, ou analysees il y a trop longtemps.
    $maxAge = (Get-Date).ToUniversalTime().AddHours(-$FullAccessCacheHours)
    $byCacheKey = @{}; $toScan = @()
    foreach ($mb in $mailboxes) {
        $key = Get-MailboxCacheKey $mb
        $byCacheKey[$key] = $mb
        $ref = ConvertTo-MailboxRef $mb
        foreach ($p in 'Name', 'Identity', 'Id', 'Alias', 'UserPrincipalName', 'PrimarySmtpAddress', 'DistinguishedName', 'Guid', 'ExternalDirectoryObjectId') {
            $v = ConvertTo-IdentityKey "$(Get-Prop $mb $p)"
            if ($v) { $Lookup[$v] = $ref }   # evite un Get-Recipient par resultat SendAs
        }
        $entry   = if ($entries.ContainsKey($key)) { $entries[$key] } else { $null }
        $changed = Get-Prop $mb 'WhenChangedUTC'
        if (-not $entry -or $entry.ScannedUtc -lt $maxAge -or ($changed -is [datetime] -and $changed -gt $entry.ScannedUtc)) { $toScan += $mb }
    }
    foreach ($key in @($entries.Keys)) { if (-not $byCacheKey.ContainsKey($key)) { $entries.Remove($key) } }   # boites supprimees

    Write-Host ("      FullAccess : {0} boite(s) [{1}] - {2} a analyser, {3} depuis le cache" -f
        $mailboxes.Count, ($FullAccessMailboxTypes -join ', '), $toScan.Count, ($mailboxes.Count - $toScan.Count)) -ForegroundColor Gray
    $failures = @(Update-FullAccessCache $toScan)

    # Une boite trouvee dans le cache est relue en direct : jamais de resultat perime affiche.
    $index   = New-TargetIdentityIndex $Items
    $scanned = @{}; foreach ($mb in $toScan) { $scanned[(Get-MailboxCacheKey $mb)] = $true }
    $recheck = @(Get-FullAccessHits $index | ForEach-Object { $_.CacheKey } | Sort-Object -Unique |
                 Where-Object { -not $scanned.ContainsKey($_) } | ForEach-Object { $byCacheKey[$_] })
    if ($recheck.Count) { $failures += @(Update-FullAccessCache $recheck) }

    # Nom, adresse et litige viennent de l'inventaire du jour, pas du cache.
    foreach ($hit in @(Get-FullAccessHits $index)) {
        Add-Delegation $ByKey[$hit.ItemKey] (ConvertTo-MailboxRef $byCacheKey[$hit.CacheKey]) 'FullAccess' $hit.CacheKey
    }
    Save-FullAccessCache
    return $failures
}

function Show-DelegationReport {
    param([Parameter(Mandatory)][object[]]$Items)
    Write-Host "`n============ BOITES AUX LETTRES ACCESSIBLES ============" -ForegroundColor Cyan
    $none = @()
    foreach ($it in $Items) {
        $groups = @(@($it.Delegations) | Group-Object MailboxId)
        if (-not $groups.Count) { $none += $it.UPN; continue }
        Write-Host ("{0} : {1} boite(s)" -f $it.UPN, $groups.Count) -ForegroundColor Red
        foreach ($g in $groups) {
            Write-Host ("  - {0} : {1}" -f (Format-MailboxLabel $g.Group[0]), (@($g.Group | ForEach-Object { $_.PermissionType }) -join ', ')) -ForegroundColor Red
        }
    }
    if ($none.Count) { Write-Host "Aucune delegation : $($none -join ', ')" -ForegroundColor Green }
}

function Remove-MailboxDelegation {
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

function ConvertFrom-ColumnLetters {
    param([string]$Letters)
    $n = 0
    foreach ($ch in $Letters.ToUpperInvariant().ToCharArray()) { $n = $n * 26 + ([int]$ch - 64) }
    return $n - 1
}

# Lignes de chaque feuille d'un .xlsx (tableaux de cellules, dans l'ordre des
# colonnes), lues directement dans l'archive OpenXML : ni Excel (COM) ni module
# ImportExcel requis. CSV / TXT : une feuille, separateur ; , ou tabulation.
function Get-WorkbookRows {
    param([Parameter(Mandatory)][string]$Path)

    $ext  = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    $rows = New-Object System.Collections.Generic.List[object]
    if ($ext -eq '.xls') { throw 'Format .xls non pris en charge : enregistrer le fichier en .xlsx.' }
    if ($ext -ne '.xlsx') {
        $lines = @([IO.File]::ReadAllLines($Path) | Where-Object { $_.Trim() })
        $delim = ';'
        if ($lines.Count) { foreach ($d in ';', ',', "`t") { if ($lines[0].Contains($d)) { $delim = $d; break } } }
        foreach ($l in $lines) { $rows.Add([string[]]@($l -split [regex]::Escape($delim) | ForEach-Object { $_.Trim().Trim('"') })) }
        return [pscustomobject]@{ Sheet = ''; Rows = $rows }
    }

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

            $rows = New-Object System.Collections.Generic.List[object]
            foreach ($row in @($data.SelectNodes("//*[local-name()='row']"))) {
                $cells = @{}; $next = 0
                foreach ($cell in @($row.SelectNodes("*[local-name()='c']"))) {
                    $col  = if ($cell.GetAttribute('r') -match '^([A-Za-z]+)') { ConvertFrom-ColumnLetters $Matches[1] } else { $next }
                    $next = $col + 1
                    $v    = $cell.SelectSingleNode("*[local-name()='v']")
                    $cells[$col] = switch ($cell.GetAttribute('t')) {
                        's'         { if ($v) { $shared[[int]$v.InnerText] } }
                        'inlineStr' { $cell.InnerText }
                        default     { if ($v) { $v.InnerText } }
                    }
                }
                if (-not $cells.Count) { continue }
                $max = ($cells.Keys | Measure-Object -Maximum).Maximum
                $rows.Add([string[]]@(0..$max | ForEach-Object { if ($cells.ContainsKey($_)) { "$($cells[$_])".Trim() } else { '' } }))
            }
            [pscustomobject]@{ Sheet = $sheet.GetAttribute('name'); Rows = $rows }
        }
    }
    finally {
        if ($zip) { $zip.Dispose() }
        $stream.Dispose()
    }
}

<#
    Adresse (minuscules) -> libelles "Editeur (feuille X) - Produit : ..., Type : ...".
    Le type de licence vient des colonnes dont l'en-tete l'evoque
    ($LicenseTypeColumnPattern). L'en-tete retenu est la derniere ligne sans
    adresse avant les donnees (une ligne de titre au-dessus est ignoree). Sans
    en-tete, les autres cellules de la ligne sont reprises.
#>
function New-LicenseIndex {
    param([object[]]$Files)
    $index = @{}
    foreach ($lf in @($Files)) {
        if (-not (Test-Path -LiteralPath $lf.Path -PathType Leaf)) { Write-Warning "[Licences] Fichier absent : $($lf.Path)"; continue }
        try { $sheets = @(Get-WorkbookRows $lf.Path) }
        catch { Write-Warning "[Licences] Lecture impossible de $($lf.Path) : $($_.Exception.Message)"; continue }

        foreach ($s in $sheets) {
            $label  = if ($s.Sheet) { "$($lf.Name) (feuille $($s.Sheet))" } else { $lf.Name }
            $header = $null; $typeCols = @(); $dataStarted = $false
            foreach ($row in $s.Rows) {
                $emails = @($EmailRegex.Matches(($row -join ' ')) | ForEach-Object { $_.Value.ToLowerInvariant() } | Sort-Object -Unique)
                if (-not $emails.Count) {
                    if (-not $dataStarted -and @($row | Where-Object { $_ }).Count) {
                        $header   = $row
                        $typeCols = @(for ($c = 0; $c -lt $row.Count; $c++) { if ($row[$c] -match $LicenseTypeColumnPattern) { $c } })
                    }
                    continue
                }
                $dataStarted = $true
                $details = @(if ($typeCols.Count) { $typeCols | Where-Object { $_ -lt $row.Count -and $row[$_] } | ForEach-Object { "$($header[$_]) : $($row[$_])" } }
                             elseif ($null -eq $header) { $row | Where-Object { $_ -and $_ -notmatch '@' } | Select-Object -First 3 })
                $entry = if ($details.Count) { "$label - $($details -join ', ')" } else { $label }
                foreach ($k in $emails) {
                    if (-not $index.ContainsKey($k)) { $index[$k] = @() }
                    if ($index[$k] -notcontains $entry) { $index[$k] += $entry }
                }
            }
        }
    }
    return $index
}

# ---------- Licences Microsoft 365 (Microsoft Graph) ---------------

# Noms officiels des references les plus courantes (doc Microsoft, aout 2026).
# Les autres viennent du CSV Microsoft, ou a defaut restent en code brut.
$script:BuiltInSkuNames = @{
    'STANDARDPACK' = 'Office 365 E1'; 'ENTERPRISEPACK' = 'Office 365 E3'; 'ENTERPRISEPREMIUM' = 'Office 365 E5'
    'Office_365_E3_(no_Teams)' = 'Office 365 E3 (no Teams)'; 'DESKLESSPACK' = 'Office 365 F3'
    'SPE_E3' = 'Microsoft 365 E3'; 'SPE_E5' = 'Microsoft 365 E5'; 'SPE_F1' = 'Microsoft 365 F3'; 'M365_F1' = 'Microsoft 365 F1'
    'Microsoft_365_E3_(no_Teams)' = 'Microsoft 365 E3 (no Teams)'; 'Microsoft_365_E5_(no_Teams)' = 'Microsoft 365 E5 (no Teams)'
    'SPB' = 'Microsoft 365 Business Premium'; 'O365_BUSINESS_PREMIUM' = 'Microsoft 365 Business Standard'
    'O365_BUSINESS_ESSENTIALS' = 'Microsoft 365 Business Basic'; 'O365_BUSINESS' = 'Microsoft 365 Apps for Business'
    'OFFICESUBSCRIPTION' = 'Microsoft 365 Apps for enterprise'
    'EXCHANGESTANDARD' = 'Exchange Online (Plan 1)'; 'EXCHANGEENTERPRISE' = 'Exchange Online (Plan 2)'
    'EXCHANGEDESKLESS' = 'Exchange Online Kiosk'; 'EXCHANGEARCHIVE_ADDON' = 'Exchange Online Archiving for Exchange Online'
    'EMS' = 'Enterprise Mobility + Security E3'; 'EMSPREMIUM' = 'Enterprise Mobility + Security E5'
    'AAD_PREMIUM' = 'Microsoft Entra ID P1'; 'AAD_PREMIUM_P2' = 'Microsoft Entra ID P2'; 'INTUNE_A' = 'Intune'
    'ATP_ENTERPRISE' = 'Microsoft Defender for Office 365 (Plan 1)'; 'THREAT_INTELLIGENCE' = 'Microsoft Defender for Office 365 (Plan 2)'
    'WIN_DEF_ATP' = 'Microsoft Defender for Endpoint'; 'RIGHTSMANAGEMENT' = 'Azure Information Protection Plan 1'
    'POWER_BI_PRO' = 'Power BI Pro'; 'POWER_BI_STANDARD' = 'Microsoft Fabric (Free)'; 'PBI_PREMIUM_PER_USER' = 'Power BI Premium Per User'
    'FLOW_FREE' = 'Microsoft Power Automate Free'; 'FLOW_PER_USER' = 'Power Automate per user plan'
    'POWERAPPS_PER_USER' = 'Power Apps Premium'; 'POWERAPPS_DEV' = 'Microsoft PowerApps for Developer'
    'PROJECT_P1' = 'Planner Plan 1'; 'PROJECTPROFESSIONAL' = 'Planner and Project Plan 3'; 'PROJECTPREMIUM' = 'Project Online Premium'
    'VISIOONLINE_PLAN1' = 'Visio Plan 1'; 'VISIOCLIENT' = 'Visio Plan 2'
    'MCOEV' = 'Microsoft Teams Phone Standard'; 'MCOMEETADV' = 'Microsoft 365 Audio Conferencing'
    'PHONESYSTEM_VIRTUALUSER' = 'Microsoft Teams Phone Resource Account'
    'TEAMS_EXPLORATORY' = 'Microsoft Teams Exploratory'; 'Microsoft_Teams_Enterprise_New' = 'Microsoft Teams Enterprise'
    'Microsoft_365_Copilot' = 'Copilot for Microsoft 365'; 'STREAM' = 'Microsoft Stream'
}

# Table integree completee par le CSV officiel Microsoft (telecharge, puis
# reutilise 30 jours). Hors ligne, la table integree suffit.
function Get-SkuDisplayNames {
    $names = @{}
    foreach ($k in $script:BuiltInSkuNames.Keys) { $names[$k] = $script:BuiltInSkuNames[$k] }
    if (-not $LicenseNamesCsvUrl) { return $names }
    $path = Join-Path $ExportRoot 'M365_LicenseNames.csv'
    try {
        if (-not (Test-Path -LiteralPath $path) -or (Get-Item -LiteralPath $path).LastWriteTime -lt (Get-Date).AddDays(-30)) {
            Invoke-WebRequest -Uri $LicenseNamesCsvUrl -OutFile "$path.tmp" -UseBasicParsing -TimeoutSec 15
            Move-Item -LiteralPath "$path.tmp" -Destination $path -Force -WhatIf:$false
        }
        foreach ($row in @(Import-Csv -LiteralPath $path)) {
            $id = "$(Get-Prop $row 'String_Id')"; $name = "$(Get-Prop $row 'Product_Display_Name')"
            if ($id -and $name) { $names[$id] = $name }
        }
    }
    catch { Write-Verbose "Noms officiels des licences indisponibles : $($_.Exception.Message)" }
    return $names
}

function Connect-GraphIfNeeded {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Warning 'Module Microsoft.Graph.Authentication absent : licences Microsoft 365 non affichees (Install-Module Microsoft.Graph.Authentication -Scope CurrentUser).'
        return $false
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -WarningAction SilentlyContinue
    if (Get-MgContext) { return $true }
    $connectArgs = @{ Scopes = $GraphScopes }
    if ((Get-Command Connect-MgGraph).Parameters.ContainsKey('NoWelcome')) { $connectArgs.NoWelcome = $true }
    Connect-MgGraph @connectArgs | Out-Null
    $script:GraphConnectedHere = $true
    return $true
}

function Resolve-GraphGroupName {
    param([string]$GroupId, [Parameter(Mandatory)][hashtable]$Cache)
    if (-not $Cache.ContainsKey($GroupId)) {
        try { $Cache[$GroupId] = "$(Get-Prop (Invoke-MgGraphRequest -Method GET -Uri ('v1.0/groups/{0}?$select=displayName' -f $GroupId) -ErrorAction Stop) 'displayName')" }
        catch { $Cache[$GroupId] = $GroupId }   # droit GroupMember.Read.All absent : identifiant brut
    }
    return $Cache[$GroupId]
}

# Licences Microsoft 365 de chaque utilisateur, avec le groupe qui les attribue
# le cas echeant : retirer ce groupe AD retire aussi la licence.
function Add-M365Licenses {
    param([Parameter(Mandatory)][object[]]$Items)
    $names  = Get-SkuDisplayNames
    $groups = @{}
    $sw     = [Diagnostics.Stopwatch]::StartNew()
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $it = $Items[$i]
        Write-ScanProgress 'Licences Microsoft 365' ($i + 1) $Items.Count $sw $it.UPN
        # L'ObjectId Entra (ExternalDirectoryObjectId) evite tout souci d'echappement de l'UPN.
        $id = "$(Get-Prop $it.Recipient 'ExternalDirectoryObjectId')"
        if (-not $id) { $id = [uri]::EscapeDataString($it.UPN) }
        try {
            $details = @(Get-Prop (Invoke-WithRetry { Invoke-MgGraphRequest -Method GET -Uri ('v1.0/users/{0}/licenseDetails?$select=skuId,skuPartNumber' -f $id) -ErrorAction Stop }) 'value' | Where-Object { $_ })
            $states  = @()
            try { $states = @(Get-Prop (Invoke-WithRetry { Invoke-MgGraphRequest -Method GET -Uri ('v1.0/users/{0}?$select=licenseAssignmentStates' -f $id) -ErrorAction Stop }) 'licenseAssignmentStates' | Where-Object { $_ }) }
            catch { Write-Verbose "licenseAssignmentStates '$($it.UPN)' : $($_.Exception.Message)" }

            $it.M365Licenses = @(foreach ($d in $details) {
                $sku   = "$(Get-Prop $d 'skuPartNumber')"
                $label = if ($names.ContainsKey($sku)) { "$($names[$sku]) ($sku)" } else { $sku }
                $via   = @($states | Where-Object { "$(Get-Prop $_ 'skuId')" -eq "$(Get-Prop $d 'skuId')" -and (Get-Prop $_ 'assignedByGroup') } |
                           ForEach-Object { Resolve-GraphGroupName "$(Get-Prop $_ 'assignedByGroup')" $groups })
                if ($via.Count) { $label += " - via groupe $($via -join ', ')" }
                $label
            })
            $it.M365Checked = $true
        }
        catch { $it.Anomalies += "[!] Lecture des licences Microsoft 365 impossible : $($_.Exception.Message)" }
    }
    Write-Progress -Activity 'Licences Microsoft 365' -Completed
}

function Show-LicenseReport {
    param([Parameter(Mandatory)][object[]]$Items)
    Write-Host "`n======================= LICENCES =======================" -ForegroundColor Cyan
    foreach ($it in $Items) {
        if (-not $it.M365Checked -and -not @($it.AppLicenses).Count) { continue }
        Write-Host $it.UPN -ForegroundColor White
        if ($it.M365Checked) {
            $m365 = if (@($it.M365Licenses).Count) { @($it.M365Licenses) -join ' | ' } else { 'aucune' }
            Write-Host "  Microsoft 365 : $m365"
        }
        foreach ($l in @($it.AppLicenses)) { Write-Host "  Applicative   : $l" -ForegroundColor Yellow }
    }
}

# ====================================================================
# DECISIONS, EXECUTION
# ====================================================================

function Show-UserSummary {
    param([Parameter(Mandatory)]$Item)

    Write-Host "`n================ $($Item.UPN) ================" -ForegroundColor Cyan
    if ($Item.LitigationHold) { Write-Host "!!! MISE EN LITIGE : Litigation Hold $($Item.LitigationHold) !!!" -ForegroundColor Red }
    $ad = $Item.ADUser
    Write-Host ("[AD] {0} | Actif : {1} | {2} groupe(s)" -f $ad.SamAccountName, $ad.Enabled, @($Item.ADGroupDNs).Count)

    if ($Item.Mailbox) {
        Write-Host ("[Exchange] {0} | {1}" -f (Get-Prop $Item.Mailbox 'PrimarySmtpAddress'), (Get-Prop $Item.Mailbox 'RecipientTypeDetails'))
    }
    elseif ($Item.Recipient) { Write-Host "[Exchange] Pas de BAL - destinataire $(Get-Prop $Item.Recipient 'RecipientTypeDetails')" }

    if ($Item.M365Checked) {
        Write-Host ("[Licences Microsoft 365] {0}" -f $(if (@($Item.M365Licenses).Count) { @($Item.M365Licenses) -join ' | ' } else { 'aucune' }))
    }

    if (@($Item.DLEntries).Count) {
        Write-Host ("[DL] {0} : {1}" -f @($Item.DLEntries).Count, (@($Item.DLEntries | ForEach-Object { $_.DisplayName }) -join ', '))
    }

    $idx = 0
    foreach ($p in @($Item.Delegations)) {
        if ($idx -eq 0) { Write-Host '[Boites aux lettres accessibles]' -ForegroundColor Red }
        $idx++
        Write-Host ("  {0}. {1} : {2}" -f $idx, (Format-MailboxLabel $p), $p.PermissionType) -ForegroundColor Red
    }

    # La mise en litige est deja en bandeau en tete du resume.
    foreach ($a in @($Item.Anomalies | Where-Object { $_ -notlike '`[!`] MISE EN LITIGE*' })) { Write-Host "  $a" -ForegroundColor Yellow }
}

function Select-DelegationRemoval {
    param([Parameter(Mandatory)]$Item)
    $all = @($Item.Delegations)
    $d = Read-Choice "Retirer les $($all.Count) delegation(s) de $($Item.UPN) ? (O = toutes / N = aucune / D = au cas par cas)" 'O', 'N', 'D'
    $Item.DelegationDecision = $d
    $Item.DelegationsToRemove = @(switch ($d) {
        'O' { $all }
        'D' { $all | Where-Object { (Read-Choice ("  Retirer {0} sur {1} ? (O/N)" -f $_.PermissionType, $_.MailboxDisplayName)) -eq 'O' } }
    })
    if ($d -eq 'D') { $Item.DelegationDecision = "Detail ($(@($Item.DelegationsToRemove).Count)/$($all.Count))" }
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

    # 1. Delegations sur boites aux lettres (uniquement celles selectionnees)
    $toRemove = @($User.DelegationsToRemove)
    foreach ($perm in $toRemove) {
        Invoke-OffboardingStep $User ("Retrait {0} sur '{1}'" -f $perm.PermissionType, $perm.MailboxDisplayName) {
            Remove-MailboxDelegation $perm $id
        }
        # Boite relue a la prochaine analyse : le cache ne doit pas survivre au retrait.
        if ($perm.CacheKey -and -not $WhatIfPreference -and $null -ne $script:FullAccessCache) {
            $script:FullAccessCache.Mailboxes.Remove($perm.CacheKey)
        }
    }
    foreach ($perm in @($User.Delegations | Where-Object { $toRemove -notcontains $_ })) {
        $User.Journal += "Conservee : $($perm.PermissionType) sur '$($perm.MailboxDisplayName)'"
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
    $perms  = @($Item.Delegations)
    $byType = {
        param([string]$Type)
        Join-Values @($perms | Where-Object { $_.PermissionType -eq $Type } | ForEach-Object { Format-MailboxLabel $_ })
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
        MembreBAL                 = $(if ($perms.Count) { 'Oui' } else { 'Non' })
        NbDelegationsBAL          = $perms.Count
        BALFullAccess             = & $byType 'FullAccess'
        BALSendAs                 = & $byType 'SendAs'
        BALSendOnBehalf           = & $byType 'SendOnBehalf'
        DecisionRetraitBAL        = $Item.DelegationDecision
        NbBALSelectionnees        = @($Item.DelegationsToRemove).Count
        EstMembrePowerPDF         = $(if ($Item.IsMemberOfPowerPDFGroup) { 'Oui' } else { 'Non' })
        MiseEnLitige              = $(if ($Item.LitigationHold) { "Oui ($($Item.LitigationHold))" } else { 'Non' })
        LicencesM365              = $(if (-not $Item.M365Checked) { '' } elseif (@($Item.M365Licenses).Count) { Join-Values $Item.M365Licenses } else { 'Aucune' })
        LicencesApplicatives      = Join-Values $Item.AppLicenses
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
            $connectArgs = @{ ShowBanner = $false }
            # Connexion plus rapide (V3) : les formats d'affichage Exchange ne sont pas utilises.
            if ((Get-Command Connect-ExchangeOnline).Parameters.ContainsKey('SkipLoadingFormatData')) { $connectArgs.SkipLoadingFormatData = $true }
            try { Connect-ExchangeOnline @connectArgs | Out-Null; $exoConnectedHere = $true }
            catch { throw "Connexion Exchange Online impossible : $($_.Exception.Message)" }
        }

        Write-Host '[2/5] Exchange : boites aux lettres et regles Inbox...' -ForegroundColor Yellow
        $phase = [Diagnostics.Stopwatch]::StartNew()
        Resolve-ExchangeRecipients $adItems
        $exoItems = @($adItems | Where-Object { $_.Recipient })
        Write-Host ("      {0} destinataire(s), dont {1} boite(s) aux lettres ({2})" -f
            $exoItems.Count, @($exoItems | Where-Object { $_.Mailbox }).Count, (Format-Duration $phase.Elapsed)) -ForegroundColor Gray
        $onHold = @($exoItems | Where-Object { $_.LitigationHold })
        if ($onHold.Count) { Show-LitigationAlert $onHold }

        # ---------------- 3. LISTES DE DISTRIBUTION -----------------
        if ($exoItems.Count) {
            Write-Host '[3/5] Listes de distribution...' -ForegroundColor Yellow
            $phase = [Diagnostics.Stopwatch]::StartNew()
            Find-UserDistributionGroups $exoItems
            $nbDL = 0; foreach ($it in $exoItems) { $nbDL += @($it.DLEntries).Count }
            Write-Host "      $nbDL appartenance(s) ($(Format-Duration $phase.Elapsed))" -ForegroundColor Gray
        }
        else { Write-Host '[3/5] Listes de distribution : aucun utilisateur concerne, ignore' -ForegroundColor Gray }

        # ---------------- 4. DELEGATIONS SUR BOITES AUX LETTRES -----
        if (-not $ScanMailboxDelegations) { Write-Host '[4/5] Delegations : desactive' -ForegroundColor Gray }
        elseif (-not $exoItems.Count) { Write-Host '[4/5] Delegations : aucun utilisateur concerne, ignore' -ForegroundColor Gray }
        else {
            Write-Host '[4/5] Delegations sur les boites aux lettres...' -ForegroundColor Yellow
            $byKey = @{}; foreach ($it in $exoItems) { $byKey[$it.Key] = $it }
            $lookup = @{}

            if ($DelegationTypes -contains 'FullAccess') {
                $phase = [Diagnostics.Stopwatch]::StartNew()
                try {
                    $failures = @(Find-FullAccessDelegations -Items $exoItems -ByKey $byKey -Lookup $lookup)
                    if ($failures.Count) {
                        Write-Warning ("{0} boite(s) illisible(s), FullAccess possiblement incomplet : {1}" -f $failures.Count, (@($failures | Select-Object -First 5) -join ' ; '))
                        $failures | ForEach-Object { Write-Verbose $_ }
                    }
                }
                catch {
                    Write-Warning "Analyse FullAccess impossible : $($_.Exception.Message)"
                    foreach ($it in $exoItems) { $it.Anomalies += '[!] Analyse FullAccess impossible' }
                }
                Write-Host "      FullAccess : termine ($(Format-Duration $phase.Elapsed))" -ForegroundColor Gray
            }
            if ($DelegationTypes -contains 'SendAs') {
                $phase = [Diagnostics.Stopwatch]::StartNew()
                Find-SendAsDelegations -Items $exoItems -Lookup $lookup
                Write-Host "      SendAs : termine ($(Format-Duration $phase.Elapsed))" -ForegroundColor Gray
            }
            if ($DelegationTypes -contains 'SendOnBehalf') {
                $phase = [Diagnostics.Stopwatch]::StartNew()
                Find-SendOnBehalfDelegations -Items $exoItems
                Write-Host "      SendOnBehalf : termine ($(Format-Duration $phase.Elapsed))" -ForegroundColor Gray
            }

            foreach ($it in $exoItems) {
                $n = @(@($it.Delegations) | Group-Object MailboxId).Count
                if ($n) {
                    $it.Delegations = @($it.Delegations | Sort-Object MailboxDisplayName, PermissionType)
                    $it.Anomalies  += "[!] Delegation(s) sur $n boite(s) aux lettres"
                }
            }
            Show-DelegationReport $exoItems
        }
    }

    # ---------------- 5. LICENCES -----------------------------------
    Write-Host '[5/5] Licences...' -ForegroundColor Yellow
    if ($ShowM365Licenses -and $adItems.Count) {
        $phase = [Diagnostics.Stopwatch]::StartNew()
        try {
            if (Connect-GraphIfNeeded) {
                Add-M365Licenses $adItems
                Write-Host "      Microsoft 365 : termine ($(Format-Duration $phase.Elapsed))" -ForegroundColor Gray
            }
        }
        catch { Write-Warning "Licences Microsoft 365 indisponibles : $($_.Exception.Message)" }
    }
    $licenseIndex = New-LicenseIndex $LicenseFiles
    foreach ($it in $items) {
        $it.AppLicenses = @($it.Addresses | Where-Object { $licenseIndex.ContainsKey($_) } | ForEach-Object { $licenseIndex[$_] } | Sort-Object -Unique)
        if ($it.AppLicenses.Count -and $it.ADUser) { $it.Anomalies += '[!] Licence(s) applicative(s) : ' + ($it.AppLicenses -join ' | ') }
    }
    Write-Host "      Applicatives : $(@($items | Where-Object { @($_.AppLicenses).Count }).Count) utilisateur(s) concerne(s)" -ForegroundColor Gray
    Show-LicenseReport $items

    # ---------------- REVUE : seulement les utilisateurs concernes ---
    # La liste numerotee des delegations sert au choix D (au cas par cas).
    $ready = @()
    foreach ($it in $adItems) {
        if (@($it.Anomalies).Count) {
            Show-UserSummary $it
            $it.DecisionAnomalies = Read-Choice "Continuer pour $($it.UPN) malgre les anomalies ? (O/N)"
            $it.DateDecision      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            if ($it.DecisionAnomalies -ne 'O') { $it.StatutExecution = 'Bloque apres analyse des anomalies'; continue }
        }
        if (@($it.Delegations).Count) { Select-DelegationRemoval $it }
        $ready += $it
    }

    # ---------------- RESUME ET CONFIRMATION UNIQUE -----------------
    Write-Host "`n================ RESUME GLOBAL ================" -ForegroundColor Cyan
    Write-Host ("Total : {0} | Prets : {1} | Bloques : {2} | Introuvables AD : {3}" -f
        $items.Count, $ready.Count, ($adItems.Count - $ready.Count), ($items.Count - $adItems.Count))
    $onHold = @($adItems | Where-Object { $_.LitigationHold })
    if ($onHold.Count) { Write-Host "ALERTE - boite(s) en litige : $(@($onHold | ForEach-Object { $_.UPN }) -join ', ')" -ForegroundColor Red }

    $decision = 'N'
    if ($ready.Count) {
        $plan = @($ready | ForEach-Object {
            [pscustomobject]@{
                UPN         = $_.UPN
                GroupesAD   = @($_.ADGroupDNs | Where-Object { -not (Test-IsProtectedGroupDN $_) }).Count
                DL          = @($_.DLEntries | Where-Object { -not (Get-Prop $_ 'IsDirSynced') }).Count
                Delegations = '{0}/{1}' -f @($_.DelegationsToRemove).Count, @($_.Delegations).Count
                Litige      = $(if ($_.LitigationHold) { 'OUI' } else { '' })
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

    Save-FullAccessCache
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
    if ($script:GraphConnectedHere) { try { Disconnect-MgGraph | Out-Null } catch {} }
}
