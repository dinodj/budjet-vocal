<#
.SYNOPSIS
    Complète la colonne « Mail Principal Syncro » d'un fichier Excel avec l'adresse mail
    des utilisateurs trouvés dans l'Active Directory.

.DESCRIPTION
    Pour chaque ligne du fichier Excel, le script lit le nom de la colonne « Nom et prénom »
    (format « NOM PRENOM »), cherche l'utilisateur correspondant dans l'AD et écrit son
    adresse mail dans la colonne « Mail Principal Syncro ».

    L'AD est uniquement lu, jamais modifié. Le fichier source n'est pas modifié non plus :
    le résultat est enregistré dans un nouveau fichier <nom>_AD_<date>.xlsx du dossier
    -OutputFolder, avec un rapport CSV <nom>_AD_<date>_rapport.csv qui détaille chaque ligne.

    Comparaison des noms (sans tenir compte de la casse, des accents, des tirets ni des apostrophes) :
      1. Exacte         : « NOM PRENOM » ou « PRENOM NOM » (Surname / GivenName), DisplayName ou CN.
      2. Ordre des mots : les mêmes mots dans un autre ordre (noms composés).
      3. Approximative  : nom tronqué dans l'Excel (ex. « DUPONT JEAN-BAPTIST »). Ces lignes sont
                          seulement signalées dans le rapport, sauf avec -IncludeApproximate.

    Adresse retenue : attribut « mail », sinon l'adresse SMTP principale (« SMTP: » dans
    proxyAddresses). Si plusieurs comptes correspondent, ceux qui sont activés et ont une
    adresse passent en premier ; s'ils ont des adresses différentes, la ligne est marquée
    AMBIGU et laissée vide.

    Statuts du rapport :
      OK              adresse écrite dans l'Excel
      DEJA OK         la cellule contenait déjà la même adresse
      DEJA RENSEIGNE  la cellule contenait une autre adresse, conservée (voir -Force)
      A VERIFIER      correspondance approximative, non écrite (voir -IncludeApproximate)
      AMBIGU          plusieurs comptes avec des adresses différentes, non écrite
      SANS MAIL       compte trouvé mais sans adresse mail
      NON TROUVE      aucun compte AD correspondant

.PARAMETER Path
    Fichier Excel à traiter. S'il n'est pas indiqué, le chemin est demandé au lancement.

.PARAMETER OutputFolder
    Dossier où enregistrer le fichier Excel produit et le rapport. S'il n'existe pas,
    le dossier du fichier source est utilisé.

.PARAMETER WorksheetName
    Feuille à traiter. Par défaut : la première.

.PARAMETER NameColumnHeader
    En-tête de la colonne des noms (comparé sans tenir compte de la casse ni des accents).

.PARAMETER MailColumnHeader
    En-tête de la colonne à compléter. Elle est créée si elle n'existe pas.

.PARAMETER HeaderRow
    Numéro de la ligne d'en-têtes.

.PARAMETER SearchBase
    OU où chercher les utilisateurs (ex. 'OU=Utilisateurs,DC=contoso,DC=local'). Par défaut : tout le domaine.

.PARAMETER Server
    Contrôleur de domaine ou domaine à interroger.

.PARAMETER Force
    Remplace les adresses déjà présentes dans la colonne.

.PARAMETER IncludeApproximate
    Écrit aussi les adresses trouvées par correspondance approximative (nom tronqué).

.EXAMPLE
    Double-cliquer sur Update-MailPrincipalSyncroFromAD.cmd (placé à côté de ce script) :
    le script est lancé sans contrôle de signature et demande le fichier Excel à traiter.

.EXAMPLE
    .\Update-MailPrincipalSyncroFromAD.ps1 -Path .\EmailPro-manquants.xlsx

.EXAMPLE
    .\Update-MailPrincipalSyncroFromAD.ps1 -Path .\EmailPro-manquants.xlsx -SearchBase 'OU=Utilisateurs,DC=contoso,DC=local' -WhatIf

.NOTES
    Windows PowerShell 5.1. Prérequis :
      - module ActiveDirectory (RSAT) ;
      - module ImportExcel (Install-Module ImportExcel -Scope CurrentUser) ou, à défaut, Microsoft Excel.
    Conserver ce fichier en UTF-8 avec BOM pour que les accents s'affichent correctement.

    Erreur « n'est pas signé numériquement » : lancer le script par Update-MailPrincipalSyncroFromAD.cmd,
    ou par : powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Update-MailPrincipalSyncroFromAD.ps1
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Position = 0)]
    [string]$Path,

    [string]$OutputFolder = 'C:\Users\Azedine.Djebbouri\OneDrive - PONTICELLI FRERES\Documents',

    [string]$WorksheetName,

    [string]$NameColumnHeader = 'Nom et prenom',

    [string]$MailColumnHeader = 'Mail Principal Syncro',

    [ValidateRange(1, 1000)]
    [int]$HeaderRow = 1,

    [string]$SearchBase,

    [string]$Server,

    [switch]$Force,

    [switch]$IncludeApproximate
)

$ErrorActionPreference = 'Stop'

#region Fonctions

# Met un nom sous une forme comparable : majuscules, sans accents, mots séparés par un espace.
# « Jean-Jacques D'Hérouville » -> « JEAN JACQUES D HEROUVILLE »
function ConvertTo-NormalizedName {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $t = ($Text.Normalize([Text.NormalizationForm]::FormD) -replace '\p{Mn}+', '').ToUpperInvariant()
    # Lettres sans décomposition Unicode : Œ, Æ, ß, Ø
    $t = $t.Replace([string][char]0x0152, 'OE').Replace([string][char]0x00C6, 'AE').Replace([string][char]0x00DF, 'SS').Replace([string][char]0x00D8, 'O')
    return ($t -creplace '[^A-Z0-9]+', ' ').Trim()
}

# Clé indépendante de l'ordre des mots : « DA SILVA JEAN MICHEL » -> « DA JEAN MICHEL SILVA »
function Get-SortedTokenKey {
    param([string]$NormalizedName)
    if (-not $NormalizedName) { return '' }
    $tokens = $NormalizedName.Split(' ')
    [Array]::Sort($tokens, [StringComparer]::Ordinal)
    return $tokens -join ' '
}

function Add-IndexEntry {
    param([hashtable]$Index, [string]$Key, [string]$Value)
    if (-not $Key) { return }
    if (-not $Index.ContainsKey($Key)) {
        $Index[$Key] = New-Object 'System.Collections.Generic.HashSet[string]'
    }
    [void]$Index[$Key].Add($Value)
}

function Get-IndexEntry {
    param([hashtable]$Index, [string]$Key)
    if ($Key -and $Index.ContainsKey($Key)) { $Index[$Key] }
}

# Comptes dont le nom commence par le nom Excel (nom tronqué dans l'Excel).
function Find-PrefixEntry {
    param([string[]]$SortedKeys, [hashtable]$Index, [string]$Prefix)
    # Au moins deux mots, pour éviter de tout ramener sur un nom de famille seul
    if (-not $Prefix -or $Prefix.IndexOf(' ') -lt 0) { return }
    $i = [Array]::BinarySearch($SortedKeys, $Prefix, [StringComparer]::Ordinal)
    if ($i -lt 0) { $i = -bnot $i }
    while ($i -lt $SortedKeys.Length -and $SortedKeys[$i].StartsWith($Prefix, [StringComparison]::Ordinal)) {
        $Index[$SortedKeys[$i]]
        $i++
    }
}

# Ouvre le classeur avec le module ImportExcel s'il est installé, sinon avec Excel (COM).
function Open-Workbook {
    param([string]$FullPath, [string]$SheetName)

    if (Get-Module -ListAvailable -Name ImportExcel) {
        Import-Module ImportExcel
        $package = Open-ExcelPackage -Path $FullPath
        if ($SheetName) { $sheet = $package.Workbook.Worksheets[$SheetName] } else { $sheet = $package.Workbook.Worksheets[1] }
        if (-not $sheet) {
            $package.Dispose()
            throw "Feuille '$SheetName' introuvable dans $FullPath."
        }
        return [pscustomobject]@{
            Backend    = 'ImportExcel'
            Package    = $package
            App        = $null
            Book       = $null
            Sheet      = $sheet
            LastRow    = $sheet.Dimension.End.Row
            LastColumn = $sheet.Dimension.End.Column
        }
    }

    try {
        $app = New-Object -ComObject Excel.Application
    }
    catch {
        throw 'Impossible de lire le fichier : installez le module ImportExcel (Install-Module ImportExcel -Scope CurrentUser) ou Microsoft Excel.'
    }
    $app.Visible = $false
    $app.DisplayAlerts = $false
    $book = $null
    try {
        $book = $app.Workbooks.Open($FullPath)
        if ($SheetName) { $sheet = $book.Worksheets.Item($SheetName) } else { $sheet = $book.Worksheets.Item(1) }
    }
    catch {
        if ($book) { $book.Close($false) }
        $app.Quit()
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($app)
        throw
    }
    $used = $sheet.UsedRange
    return [pscustomobject]@{
        Backend    = 'Excel'
        Package    = $null
        App        = $app
        Book       = $book
        Sheet      = $sheet
        LastRow    = $used.Row + $used.Rows.Count - 1
        LastColumn = $used.Column + $used.Columns.Count - 1
    }
}

function Get-CellText {
    param($Workbook, [int]$Row, [int]$Column)
    if ($Workbook.Backend -eq 'ImportExcel') { $value = $Workbook.Sheet.Cells[$Row, $Column].Value }
    else { $value = $Workbook.Sheet.Cells.Item($Row, $Column).Value2 }
    if ($null -eq $value) { return '' }
    return ([string]$value).Trim()
}

function Set-CellText {
    param($Workbook, [int]$Row, [int]$Column, [string]$Value)
    if ($Workbook.Backend -eq 'ImportExcel') { $Workbook.Sheet.Cells[$Row, $Column].Value = $Value }
    else { $Workbook.Sheet.Cells.Item($Row, $Column).Value2 = $Value }
}

function Save-Workbook {
    param($Workbook, [string]$FullPath)
    if ($Workbook.Backend -eq 'ImportExcel') { $Workbook.Package.SaveAs((New-Object System.IO.FileInfo $FullPath)) }
    else { $Workbook.Book.SaveAs($FullPath, 51) }   # 51 = xlOpenXMLWorkbook (.xlsx)
}

function Close-Workbook {
    param($Workbook)
    if ($Workbook.Backend -eq 'ImportExcel') {
        $Workbook.Package.Dispose()
        return
    }
    $Workbook.Book.Close($false)
    $Workbook.App.Quit()
    foreach ($com in @($Workbook.Sheet, $Workbook.Book, $Workbook.App)) {
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($com)
    }
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}

#endregion

#region Chemins

if (-not $Path) {
    do {
        # Un fichier glissé dans la fenêtre ou copié avec « Copier en tant que chemin d'accès » arrive entre guillemets
        $Path = ([string](Read-Host "Chemin du fichier Excel (glissez le fichier dans cette fenêtre, Entrée vide pour quitter)")).Trim().Trim('"')
        if (-not $Path) {
            Write-Host 'Abandon.'
            return
        }
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            Write-Warning "Fichier introuvable : $Path"
            $Path = $null
        }
    } while (-not $Path)
}
$inputFile = (Resolve-Path -LiteralPath $Path).ProviderPath

if (-not (Test-Path -LiteralPath $OutputFolder -PathType Container)) {
    $fallbackFolder = Split-Path -Parent $inputFile
    Write-Warning "Dossier de sortie introuvable : $OutputFolder. Enregistrement dans $fallbackFolder."
    $OutputFolder = $fallbackFolder
}
$OutputFolder = (Resolve-Path -LiteralPath $OutputFolder).ProviderPath

# Horodatage : ne remplace pas un résultat précédent, éventuellement encore ouvert dans Excel
$baseName = [IO.Path]::GetFileNameWithoutExtension($inputFile) + '_AD_' + (Get-Date -Format 'yyyyMMdd-HHmm')
$outputFile = Join-Path $OutputFolder ($baseName + '.xlsx')
$reportFile = Join-Path $OutputFolder ($baseName + '_rapport.csv')

#endregion

#region Chargement de l'AD

Import-Module ActiveDirectory

Write-Host "Chargement des utilisateurs de l'Active Directory..."
$adParams = @{
    Filter     = '*'
    Properties = 'DisplayName', 'mail', 'proxyAddresses'
}
if ($SearchBase) { $adParams.SearchBase = $SearchBase }
if ($Server) { $adParams.Server = $Server }

$usersByDn = @{}
$exactIndex = @{}   # nom normalisé -> DN des comptes
$tokenIndex = @{}   # mots triés    -> DN des comptes

foreach ($adUser in Get-ADUser @adParams) {
    $mail = [string]$adUser.mail
    if (-not $mail) {
        $primary = @($adUser.proxyAddresses) -cmatch '^SMTP:' | Select-Object -First 1
        if ($primary) { $mail = $primary.Substring(5) }
    }

    $dn = $adUser.DistinguishedName
    $usersByDn[$dn] = [pscustomobject]@{
        SamAccountName    = $adUser.SamAccountName
        Enabled           = [bool]$adUser.Enabled
        Mail              = $mail
        DistinguishedName = $dn
    }

    $surname = ConvertTo-NormalizedName $adUser.Surname
    $givenName = ConvertTo-NormalizedName $adUser.GivenName
    $names = @((ConvertTo-NormalizedName $adUser.DisplayName), (ConvertTo-NormalizedName $adUser.Name))
    if ($surname -and $givenName) { $names += "$surname $givenName", "$givenName $surname" }

    foreach ($name in $names) {
        Add-IndexEntry $exactIndex $name $dn
        Add-IndexEntry $tokenIndex (Get-SortedTokenKey $name) $dn
    }
}

if ($usersByDn.Count -eq 0) { throw "Aucun utilisateur trouvé dans l'AD (SearchBase : '$SearchBase')." }
Write-Host "$($usersByDn.Count) comptes chargés."

$sortedKeys = [string[]]@($exactIndex.Keys)
[Array]::Sort($sortedKeys, [StringComparer]::Ordinal)

#endregion

#region Traitement du fichier Excel

Write-Host "Lecture de $inputFile..."
$workbook = Open-Workbook -FullPath $inputFile -SheetName $WorksheetName
$results = New-Object System.Collections.Generic.List[object]

try {
    # Repérage des colonnes par leur en-tête
    $nameColumn = 0
    $mailColumn = 0
    $wantedName = ConvertTo-NormalizedName $NameColumnHeader
    $wantedMail = ConvertTo-NormalizedName $MailColumnHeader
    for ($c = 1; $c -le $workbook.LastColumn; $c++) {
        $header = ConvertTo-NormalizedName (Get-CellText $workbook $HeaderRow $c)
        if (-not $nameColumn -and $header -eq $wantedName) { $nameColumn = $c }
        elseif (-not $mailColumn -and $header -eq $wantedMail) { $mailColumn = $c }
    }
    if (-not $nameColumn) { throw "Colonne '$NameColumnHeader' introuvable en ligne $HeaderRow." }
    if (-not $mailColumn) {
        $mailColumn = $workbook.LastColumn + 1
        Set-CellText $workbook $HeaderRow $mailColumn $MailColumnHeader
        Write-Warning "Colonne '$MailColumnHeader' absente : créée en colonne $mailColumn."
    }

    for ($row = $HeaderRow + 1; $row -le $workbook.LastRow; $row++) {
        $excelName = Get-CellText $workbook $row $nameColumn
        if (-not $excelName) { continue }
        $currentMail = Get-CellText $workbook $row $mailColumn
        $key = ConvertTo-NormalizedName $excelName

        # Recherche du ou des comptes, de la correspondance la plus stricte à la plus tolérante
        $matchType = 'Exacte'
        $dns = @(Get-IndexEntry $exactIndex $key)
        if ($dns.Count -eq 0) {
            $matchType = 'Ordre des mots'
            $dns = @(Get-IndexEntry $tokenIndex (Get-SortedTokenKey $key))
        }
        if ($dns.Count -eq 0) {
            $matchType = 'Approximative'
            $dns = @(Find-PrefixEntry $sortedKeys $exactIndex $key | Select-Object -Unique)
        }
        $candidates = @($dns | ForEach-Object { $usersByDn[$_] })

        # Choix de l'adresse : comptes activés d'abord, puis désactivés
        $withMail = @($candidates | Where-Object { $_.Mail -and $_.Enabled })
        if ($withMail.Count -eq 0) { $withMail = @($candidates | Where-Object { $_.Mail }) }
        $distinctMails = @($withMail | ForEach-Object { $_.Mail.ToLowerInvariant() } | Select-Object -Unique)
        $chosen = $null
        if ($distinctMails.Count -eq 1) { $chosen = $withMail[0] }

        if ($candidates.Count -eq 0) { $status = 'NON TROUVE' }
        elseif ($distinctMails.Count -eq 0) { $status = 'SANS MAIL' }
        elseif ($distinctMails.Count -gt 1) { $status = 'AMBIGU' }
        elseif ($matchType -eq 'Approximative' -and -not $IncludeApproximate) { $status = 'A VERIFIER' }
        elseif ($currentMail -and $currentMail -eq $chosen.Mail) { $status = 'DEJA OK' }
        elseif ($currentMail -and -not $Force) { $status = 'DEJA RENSEIGNE' }
        else {
            $status = 'OK'
            Set-CellText $workbook $row $mailColumn $chosen.Mail
        }

        $results.Add([pscustomobject]@{
                Ligne            = $row
                Nom              = $excelName
                Statut           = $status
                Correspondance   = if ($candidates.Count) { $matchType } else { '' }
                MailAD           = if ($chosen) { $chosen.Mail } else { '' }
                ValeurPrecedente = $currentMail
                Compte           = if ($chosen) { $chosen.SamAccountName } else { '' }
                CompteActive     = if ($chosen) { $chosen.Enabled } else { '' }
                Candidats        = ($candidates | ForEach-Object {
                        '{0} <{1}>{2}' -f $_.SamAccountName, $_.Mail, $(if ($_.Enabled) { '' } else { ' (désactivé)' })
                    }) -join ' ; '
                DN               = if ($chosen) { $chosen.DistinguishedName } else { '' }
            })
    }

    $written = @($results | Where-Object Statut -eq 'OK').Count
    if ($PSCmdlet.ShouldProcess($outputFile, "Enregistrer le fichier Excel ($written adresse(s) ajoutée(s))")) {
        Save-Workbook $workbook $outputFile
        Write-Host "Fichier Excel enregistré : $outputFile"
    }
}
finally {
    Close-Workbook $workbook
}

if ($PSCmdlet.ShouldProcess($reportFile, 'Enregistrer le rapport CSV')) {
    $results | Export-Csv -LiteralPath $reportFile -NoTypeInformation -Delimiter ';' -Encoding UTF8 -Confirm:$false
    Write-Host "Rapport enregistré : $reportFile"
}

#endregion

#region Synthèse

Write-Host ''
Write-Host 'Synthèse :'
$results | Group-Object Statut | Sort-Object Count -Descending |
    Format-Table @{ Label = 'Statut'; Expression = { $_.Name } }, @{ Label = 'Lignes'; Expression = { $_.Count } } -AutoSize |
    Out-Host

$toCheck = @($results | Where-Object { $_.Statut -notin 'OK', 'DEJA OK' })
if ($toCheck.Count) {
    Write-Host 'Lignes à vérifier (NON TROUVE en dernier) :'
    $toCheck | Sort-Object { $_.Statut -eq 'NON TROUVE' }, Ligne |
        Format-Table Ligne, Nom, Statut, Candidats -AutoSize -Wrap |
        Out-Host
}

#endregion
