param (
    [Parameter(Mandatory=$true)]
    [string]$solutionFile,
    [Parameter(Mandatory=$false)]
    [string]$ignoreFile,
    [Parameter(Mandatory=$true)]
    [string]$outputFile
)

function Get-IgnoreList($ignoreFilePath) {
    if (Test-Path $ignoreFilePath) {
        return Get-Content -Path $ignoreFilePath
    } else {
        return @()
    }
}

function Scan-Folder($solutionFile, $ignoreList) {
    $solution = @{
        path = $solutionFile
        projects = @()
    }

    $directories = Get-ChildItem -Path "src" -Directory
    foreach ($dir in $directories) {
        if ($ignoreList -notcontains $dir.Name) {
            $csprojFiles = Get-ChildItem -Path $dir.FullName -Filter *.csproj -File -ErrorAction SilentlyContinue
            foreach ($csproj in $csprojFiles) {
                $solution.projects += "src\$($dir.Name)\$($csproj.Name)"
            }
        }
    }

    $directories = Get-ChildItem -Path "test" -Directory
    foreach ($dir in $directories) {
         if ($ignoreList -notcontains $dir.Name) {
            $csprojFiles = Get-ChildItem -Path $dir.FullName -Filter *.csproj -File -ErrorAction SilentlyContinue
            foreach ($csproj in $csprojFiles) {
                $solution.projects += "test\$($dir.Name)\$($csproj.Name)"
            }
        }
    }

    return $solution
}

function Generate-SolutionFilter {
    param (
        [Parameter(Mandatory=$true)]
        [string]$solutionFile,
        [Parameter(Mandatory=$false)]
        [string]$ignoreFile,
        [Parameter(Mandatory=$true)]
        [string]$outputFile
    )

    $ignoreList = Get-IgnoreList -ignoreFilePath $ignoreFile
    $solution = Scan-Folder -solutionFile $solutionFile -ignoreList $ignoreList

    $solutionFilter = @{
        solution = $solution
    }
    $solutionFilter | ConvertTo-Json -Depth 2 | Out-File -FilePath $outputFile
}

Generate-SolutionFilter -solutionFile $solutionFile -ignoreFile $ignoreFile -outputFile $outputFile