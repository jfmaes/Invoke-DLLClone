Function Invoke-DllClone {

<#
.SYNOPSIS  
    
    Invoke-DllClone combines two projects called Koppeling and Invoke-MetaTwin. 
    Invoke-DllClone can copy metadata and the AuthenticodeSignature from a source binary and into a target binary
    It also uses koppeling to clone the export table from a refference dll onto a malicious DLL post-build using NetClone
    Finally, it also supports random fake signatures using LazySign logic.
    
    Function: Invoke-DllClone
    Author: Jean-Francois Maes (@jfmaes), Joe Vest, monoxgas
    License: BSD 3-Clause
    Required Dependencies: ResourceHacker.exe, NetClone.exe
    Optional Dependencies: SigThief,makecert.exe,pvk2pfx.exe,signtool.exe
    
.DESCRIPTION  
         Invoke-DllClone combines two projects called Koppeling and Invoke-MetaTwin. 
         Invoke-DllClone can copy metadata and the AuthenticodeSignature from a source binary and into a target binary
         It also uses koppeling to clone the export table from a refference dll onto a malicious DLL post-build using NetClone
         Finally, it also supports random fake signatures using LazySign logic.
         Note: SigThief and Resource Hacker may not detect valid metadata or digital signature.  This project may switch to a different tool set, but for now, be aware of potential limitations.
         Note2: Feel free to compile koppeling yourself and put it in the src directory, same goes with Resoure Hacker and SigThief and the other dependencies really.
        
.LINK  
    https://github.com/monoxgas/Koppeling
    https://github.com/threatexpress/metatwin

    
.PARAMETER Source
        Path to source binary (where you want to copy the resources from)
        
.PARAMETER Target
        Path to target binary (where you want the resources copied to)
        
.PARAMETER Sign
        Switch to perform AuthenticodeSignature copying via SigThief
        
#>

Param     (
    [ValidateScript({Test-Path $_ })]
        [Parameter(Mandatory=$true,
        HelpMessage='Source binary')]
        $Source = '',
    
    [ValidateScript({Test-Path $_ })]
        [Parameter(Mandatory=$true,
        HelpMessage='Target binary')]
        $Target = '',

    [Parameter(Mandatory=$false,
        HelpMessage='output binary')]
        $Output = '',

    [Parameter(Mandatory=$false,
        HelpMessage='Include digital signature')]
        [Switch]$Sign,

    [Parameter(Mandatory=$false,
        HelpMessage='Use LazySign to create a new fake sig')]
        [Switch]$FakeSign,

    [Parameter(Mandatory=$false,
        HelpMessage='Use LazySign to create a new fake sig')]
        $FakeCompany = ''

   )

Set-StrictMode -Version 2
# Binaries
$resourceHackerBin = ".\src\Resource_Hacker\ResourceHacker.exe"
$resourceHacker_base_script = ".\src\rh_base_script.txt"
$sigthiefBin       = ".\src\SigThief\sigthief.exe"
$netcloneBin = ".\src\Koppeling\NetClone.exe"
$makecertBin = ".\src\LazySign\makecert.exe"
$pvk2pfxBin = ".\src\LazySign\pvk2pfx.exe"
$signtoolBin = ".\src\LazySign\signtool.exe"


If ((Test-Path $resourceHackerBin) -ne $True) 
    {
        Write-Output "[!] Missing Dependency: $resourceHackerBin"
        Write-Output "[!] Ensure you're running Invoke-DllClone from its local directory. Exiting"
        break
    }

If ((Test-Path $sigthiefBin) -ne $True) 
    {
        Write-Output "[!] Missing Dependency: $sigthiefBin"
        Write-Output "[!] Ensure you're running Invoke-DllClone from its local directory. Exiting."
        break
    }


If ((Test-Path $netcloneBin) -ne $True) 
    {
        Write-Output "[!] Missing Dependency: $netcloneBin"
        Write-Output "[!] Ensure you're running Invoke-DllClone from its local directory. Exiting."
        break
    }


if($FakeSign){
If ((Test-Path $makecertBin) -ne $True) 
    {
        Write-Output "[!] Missing Dependency: $makecertBin"
        Write-Output "[!] Ensure you're running Invoke-DllClone from its local directory. Exiting."
        break
    }

If ((Test-Path $pvk2pfxBin) -ne $True) 
    {
        Write-Output "[!] Missing Dependency: $pvk2pfxBin"
        Write-Output "[!] Ensure you're running Invoke-DllClone from its local directory. Exiting."
        break
    }

If ((Test-Path $signtoolBin) -ne $True) 
    {
        Write-Output "[!] Missing Dependency: $signtoolBin"
        Write-Output "[!] Ensure you're running Invoke-DllClone from its local directory. Exiting."
        break
    }

}

# Basic file timestomping, maybe redundant since it will also need to be performed on target
Function Invoke-TimeStomp ($source, $dest) {
    $source_attributes = Get-Item $source
    $dest_attributes = Get-Item $dest 
    $dest_attributes.CreationTime = $source_attributes.CreationTime
    $dest_attributes.LastAccessTime = $source_attributes.LastAccessTime
    $dest_attributes.LastWriteTime = $source_attributes.LastWriteTime
}


$timestamp = Get-Date -f yyyy-MM-dd_HHmmss
$log_file_base = (".\" + $timestamp)
$source_binary_filename = Split-Path $Source -Leaf -Resolve
$source_binary_filepath = $Source
$target_binary_filename = Split-Path $Target -Leaf -Resolve
$target_binary_filepath = $Target
$source_resource = (".\" + $timestamp + "\" + $source_binary_filename + ".res")


if(-Not $Output){
$target_saveas = (".\" + $timestamp + "\"+ $target_binary_filename)
$target_saveas_signed = (".\" + $timestamp + "\" + "signed_" + $target_binary_filename)
}
else{
    $target_saveas = (".\" + $timestamp + "\" + $Output)
    $target_saveas_signed = (".\" + $timestamp + "\" +"signed_" + $Output)
}




$resourcehacker_script = (".\"+ $timestamp + "_rh_script.txt")

New-Item ".\$timestamp" -type directory | out-null
Write-Output "Source:         $source_binary_filepath"
Write-Output "Target:         $target_binary_filepath"
Write-Output "Output:         $target_saveas"
Write-Output "Signed Output:  $target_saveas_signed"
Write-Output "---------------------------------------------- "

# start the export table cloning using koppeling
Write-Output "[*] Clones the export table from $source onto $target... using NetClone "
$arg = "--target $target --reference $source --output $target_saveas"
Start-Process -FilePath $netcloneBin -NoNewWindow -ArgumentList $arg -wait
# Clean up existing ResourceHacker.exe that may be running
Stop-Process -Name ResourceHacker -ea "SilentlyContinue"
# Extract resources using Resource Hacker from source 
Write-Output "[*] Extracting resources from $source_binary_filename "
$log_file = ($log_file_base + "\"+ $timestamp+"_extract.log")
$arg = "-open $source_binary_filepath -action extract -mask ,,, -save $source_resource -log $log_file"
start-process -FilePath $resourceHackerBin -ArgumentList $arg -NoNewWindow -Wait

# Check if extract was successful
if (Select-String -Encoding Unicode -path $log_file -pattern "Failed") {
    Write-Output "[!] Failed to extract Metadata from $source_binary_filepath"
    Write-Output "    Perhaps, try a differenct source file. Exiting..."
    break   
}


# Build Resource Hacker Script 
$log_file = ($log_file_base + "\"+ $timestamp+ "_add.log")
(Get-Content $resourcehacker_base_script) -replace('AAA', $target) | Set-Content $resourcehacker_script
(Get-Content $resourcehacker_script) -replace('BBB', $target_saveas) | Set-Content $resourcehacker_script
(Get-Content $resourcehacker_script) -replace('CCC', $log_file) | Set-Content $resourcehacker_script
(Get-Content $resourcehacker_script) -replace('DDD', $source_resource) | Set-Content $resourcehacker_script

# Copy resources using Resource Hacker
"[*] Copying resources from $source_binary_filename to $target_saveas"

$arg = "-script $resourcehacker_script"
start-process -FilePath $resourceHackerBin -ArgumentList $arg -NoNewWindow -Wait
Remove-Item $resourcehacker_script


if ($Sign) {

    # Copy signature from source and add to target
    "[*] Extracting and adding signature ..."
    $arg = "-i $source_binary_filepath -t $target_saveas -o $target_saveas_signed"
    $proc = start-process -FilePath $sigthiefBin -ArgumentList $arg -Wait -PassThru
    #$proc | Select * |Format-List
    #$proc.ExitCode
    if ($proc.ExitCode -ne 0) {
        Write-Output "[-] Cannot extract signature, skipping ..."     
        $Sign = $False   
    }
}

# Display Results
Start-Sleep .5
Write-Output "`n[+] Results"
Write-Output " -----------------------------------------------"


if ($Sign) {

    Write-Output "[+] Metadata"
    Get-Item $target_saveas_signed | Select VersionInfo | Format-List

    Write-Output "[+] Digital Signature"
    Get-AuthenticodeSignature (gi $target_saveas_signed) | select SignatureType,SignerCertificate,Status | fl
    Invoke-TimeStomp $source_binary_filepath $target_saveas_signed
}

elseif($FakeSign) {
    Write-Output "[+] Starting LazySign..."
    if(-Not $FakeCompany)
    {
        $FakeCompany = Read-Host -Prompt "Please Type in a company name you would like to fake a signature for" 
    }
    else
    {
     Write-Output "using " + $FakeCompany + " to fake a signature..." 
    }
    $arg = "-len 2048 " + $FakeCompany+".cer " + "-n ""CN="""+$FakeCompany + " -r -sv " + $FakeCompany+".pvk"
    Start-Process -FilePath $makecertBin -Wait -NoNewWindow -ArgumentList $arg

    $arg = "-pvk " + $FakeCompany +".pvk" + " -spc " + $FakeCompany+".cer" +" -pfx " + $FakeCompany+".pfx"
    Start-Process -FilePath $pvk2pfxBin -Wait -NoNewWindow -ArgumentList $arg

    $arg = "sign /f " + ".\"+$FakeCompany+".pfx /t http://timestamp.comodoca.com/authenticode " + $target_saveas
    Start-Process -FilePath $signtoolBin -wait -NoNewWindow -ArgumentList $arg
    Move-item $target_saveas $target_saveas_signed

    Remove-Item $FakeCompany".pfx"
    Remove-Item $FakeCompany".cer"
    Remove-Item $FakeCompany".pvk"  

    Write-Output "[+] Metadata"
    Get-Item $target_saveas_signed | Select VersionInfo | Format-List
    Write-Output "[+] Digital Signature"
    Get-AuthenticodeSignature (gi $target_saveas_signed) | select SignatureType,SignerCertificate | fl
    Invoke-TimeStomp $source_binary_filepath $target_saveas_signed
}


else {
    Write-Output "[+] Metadata"
    Get-Item $target_saveas | Select VersionInfo | Format-List
    Write-Output "[+] Digital Signature"
    Write-Output "    Signature not added ... "
    Invoke-TimeStomp $source_binary_filepath $target_saveas
}

}