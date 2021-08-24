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

```
Forward all exports of powrprof and take over the metadata except the signature
Example Usage: Invoke-DllClone -Source C:\Windows\System32\powrprof.dll -Target C:\Malware\Evilpayload.dll -Output C:\Malware\powrprof.dll

Forward all exports of powrprof and take over the metadata including the signature (will obviously no longer be valid)
Example Usage: Invoke-DllClone -Source C:\Windows\System32\powrprof.dll -Target C:\Malware\Evilpayload.dll -Output C:\Malware\powrprof.dll -Sign

Forward all exports of powrprof and take over the metadata fake a random signature (will obviously not be valid)
Example Usage: Invoke-DllClone -Source C:\Windows\System32\powrprof.dll -Target C:\Malware\Evilpayload.dll -Output C:\Malware\powrprof.dll -FakeSign -FakeCompany lolcorp.evil

```
