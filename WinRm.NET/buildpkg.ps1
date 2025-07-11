[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$VersionString
)

$scriptRoot = $PSScriptRoot
if (-not $scriptRoot) {
  $scriptRoot = (Get-Location).Path
}

$nuspecTemplatePath = join-path $scriptRoot "WinRm.NET.nuspec"
$versionedNuspecFileName = "WinRm.NET.$($VersionString).nuspec"
$versionedNuspecPath = join-path $scriptRoot $versionedNuspecFileName
Remove-Item $versionedNuspecPath -Force -ErrorAction SilentlyContinue

[xml]$nuspec = Get-Content $nuspecTemplatePath
$versionNode = $nuspec.SelectSingleNode("//version")
$versionNode.InnerText = $VersionString
$nuspec.Save($versionedNuspecPath)

$versionedNupkgFile = "WinRM.NET.$($VersionString).nupkg"
$versionedNupkgFilePath = join-path $scriptRoot $versionedNupkgFile
Remove-Item $versionedNupkgFilePath -Force -ErrorAction SilentlyContinue
dotnet pack -c Release -p:NuspecFile=$versionedNuspecFileName -o .

Write-Host "Nuspec file content:"
Get-Content $versionedNuspecPath

if (test-path $versionedNupkgFilePath) {
  $choices  = '&Yes', '&No'
  $decision = $Host.UI.PromptForChoice("Push Package", "Push to experimental repo?", $choices, 1)
  if ($decision -eq 0) {
      dotnet nuget push --source "Experimental" --api-key az $versionedNupkgFile
      remove-item $versionedNuspecPath
      remove-item $versionedNupkgFilePath
  } else {
      Write-Host 'cancelled'
  }
}
else {
  Write-Host "Expected file not found: $versionedNupkgFilePath"
}


