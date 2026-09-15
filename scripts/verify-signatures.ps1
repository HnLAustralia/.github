<#
.SYNOPSIS
    Asserts that an MSI and the executable INSIDE it are both signed.

.DESCRIPTION
    Used by the shared dotnet-windows-build workflow when sign=true, and runnable by hand
    against any built or downloaded MSI.

    The failure this exists to catch is specific and quiet: the wixproj packages whatever is
    sitting in the publish directory, so if anything re-publishes the project after the
    executable was signed, the MSI ends up signed while carrying an unsigned executable. That
    passes every check anyone thinks to run on the MSI, and fails the one that matters on the
    machine it installs to - where AV and WDAC look at the application binary, not at the
    installer that put it there.

    So this does not trust the MSI's own signature as evidence. It extracts the MSI and checks
    the executable that actually ships.

    ## Why not signtool

    signtool verifies trust, and SSL.com's public sandbox certificate (ES_ENVIRONMENT=TEST)
    chains to an untrusted test CA. `signtool verify /pa` therefore fails on a correctly signed
    file, which would leave two bad options: a check that always fails and is learned to be
    ignored, or a check loosened until it stops catching the real thing.

    Get-AuthenticodeSignature separates the two questions. `Status -eq 'NotSigned'` means no
    signature - the defect. Any other status means a signature is present, and whether the
    chain is trusted is a separate axis this script reports but does not gate on. Nothing here
    changes when the real certificate arrives; the reported status simply becomes Valid.

.PARAMETER MsiPath
    The built MSI. Required.

.PARAMETER PublishExe
    The signed executable in the publish directory, checked as well when supplied. Its result
    against the extracted copy is what localises a failure: publish signed + extracted unsigned
    means the MSI build overwrote it.

.PARAMETER ExpectedIssuer
    Substring the issuer DN must contain. Defaults to the certificate authority rather than
    the subject, because the subject is what changes: the sandbox certificate is issued to
    "Esigner LLC" and a real one is issued to the organisation. Both come from SSL Corp, so
    this gate holds across the swap instead of becoming a build failure waiting on a future
    release branch.

.PARAMETER ExpectTrusted
    Require a trusted chain, not merely a signature. Do not enable it while signing with the
    sandbox: that chain reaches no trusted root, so it would plant a red build for whoever next
    pushes a release branch. Enable it once a real certificate is in use - at that point it is
    what stops a silent downgrade back to a demo certificate. The shared workflow passes it
    automatically whenever esigner-environment is PROD.

    Note what the default gate therefore cannot do: SSL Corp issues both the demo and the real
    certificate, so nothing here distinguishes them. The artifact name carries that instead -
    the shared workflow appends -DEMO-SIGNED - which makes a demo-signed build obvious to
    anyone downloading it without failing any build.

.EXAMPLE
    ./scripts/verify-signatures.ps1 -MsiPath bin/Release/MyService.msi

.EXAMPLE
    # Against a downloaded release artefact, to answer "was this one actually signed?"
    ./scripts/verify-signatures.ps1 -MsiPath ~/Downloads/MyService.msi -ExpectTrusted
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$MsiPath,
    [string]$PublishExe,
    [string]$ExpectedIssuer = 'O=SSL Corp',
    [switch]$ExpectTrusted
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $MsiPath)) {
    throw "MSI not found: $MsiPath"
}
$MsiPath = (Resolve-Path -LiteralPath $MsiPath).Path

$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param([string]$What, [string]$Path)

    $signature = Get-AuthenticodeSignature -LiteralPath $Path

    # SignerCertificate is populated whenever a signature exists, trusted or not. Status alone
    # is not enough: it carries both "no signature" and "signature, bad chain" and the whole
    # point here is to tell those apart.
    $signed = $null -ne $signature.SignerCertificate
    $timestamped = $null -ne $signature.TimeStamperCertificate
    $issuer = if ($signed) { $signature.SignerCertificate.Issuer } else { '' }

    # A substring match on the issuer DN rather than parsing it. The organisation is the stable
    # part: the sandbox certificate is issued by "SSL.com EV Code Signing Intermediate CA RSA
    # R2" and an OV certificate comes from a differently-named intermediate, so matching the
    # issuer CN would fail on the day the real certificate arrives - the one day this must not
    # break.
    $fromExpectedIssuer = $signed -and $issuer -like "*$ExpectedIssuer*"

    $results.Add([pscustomobject]@{
        What            = $What
        Signed          = $signed
        FromIssuer      = $fromExpectedIssuer
        Timestamped     = $timestamped
        Trusted         = ($signature.Status -eq 'Valid')
        Status          = $signature.Status
        Subject         = if ($signed) { $signature.SignerCertificate.Subject } else { '-' }
        Issuer          = if ($signed) { $issuer } else { '-' }
        TimestampIssuer = if ($timestamped) { $signature.TimeStamperCertificate.Issuer } else { '-' }
        Path            = $Path
    })
}

# ---------------------------------------------------------------------------
# The MSI, and the executable it was built from
# ---------------------------------------------------------------------------

Add-Result -What 'MSI' -Path $MsiPath

if ($PublishExe) {
    if (-not (Test-Path -LiteralPath $PublishExe)) {
        throw "Publish executable not found: $PublishExe"
    }
    Add-Result -What 'Executable (publish dir)' -Path (Resolve-Path -LiteralPath $PublishExe).Path
}

# ---------------------------------------------------------------------------
# The executable that actually ships, taken out of the MSI
# ---------------------------------------------------------------------------

# An administrative install unpacks the MSI without installing it, keeping real file names.
# Native to Windows, so no lessmsi or 7-Zip dependency, and no service is registered on the
# machine running this.
$extractRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("sen96-verify-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null

try {
    $process = Start-Process -FilePath 'msiexec.exe' `
        -ArgumentList @('/a', "`"$MsiPath`"", '/qn', "TARGETDIR=`"$extractRoot`"") `
        -Wait -PassThru -NoNewWindow
    if ($process.ExitCode -ne 0) {
        throw "msiexec administrative install failed with exit code $($process.ExitCode)."
    }

    # @() because Get-ChildItem returns a bare FileInfo when it matches exactly one file, and
    # under Set-StrictMode a scalar has no Count - which is the case this check exists for.
    $extracted = @(Get-ChildItem -Path $extractRoot -Filter 'SysnetSentinelService.exe' -Recurse -File)
    if ($extracted.Count -ne 1) {
        throw ("Expected exactly one SysnetSentinelService.exe inside the MSI, found " +
               "$($extracted.Count). Extracted to $extractRoot.")
    }

    Add-Result -What 'Executable (inside MSI)' -Path $extracted[0].FullName

    $results | Format-Table What, Signed, FromIssuer, Timestamped, Trusted, Status -AutoSize |
        Out-String | Write-Host
    foreach ($r in $results) {
        Write-Host "$($r.What)"
        Write-Host "    signed by : $($r.Subject)"
        Write-Host "    issued by : $($r.Issuer)"
        Write-Host "    timestamp : $($r.TimestampIssuer)"
    }

    # -----------------------------------------------------------------------
    # Verdict
    # -----------------------------------------------------------------------

    $problems = @()

    foreach ($r in $results) {
        if (-not $r.Signed) {
            $problems += "$($r.What) is NOT SIGNED ($($r.Path))"
        }
        else {
            if (-not $r.Timestamped) {
                # Not cosmetic. Without an RFC 3161 counter-signature every signature becomes
                # invalid the day the certificate expires - retroactively, including MSIs
                # already installed at venues. With one they stay valid for the life of the
                # timestamp.
                $problems += "$($r.What) has NO TIMESTAMP ($($r.Path))"
            }

            # Deliberately gates on WHO issued it rather than on chain trust. Both the sandbox
            # certificate and the real one are issued by SSL Corp, so this passes today and
            # keeps passing after the swap - no landmine that turns CI red on a future release
            # branch. What it does catch is a signature from somewhere else entirely: the
            # organisation also holds HALDEVCERT_PFX_B64, and someone wiring that in here
            # instead would otherwise look exactly like success.
            if (-not $r.FromIssuer) {
                $problems += ("$($r.What) was not issued by '$ExpectedIssuer' - got: " +
                              "$($r.Issuer)")
            }

            # Present is not the same as INTACT, and every other column here fails to notice
            # the difference. Get-AuthenticodeSignature populates SignerCertificate whenever a
            # signature exists, so a file modified AFTER it was signed still reads as signed,
            # correctly issued and timestamped - only Status says HashMismatch. That is not a
            # chain-trust question, so it cannot wait for -ExpectTrusted, which CI does not pass
            # while the sandbox certificate is in use: without this line a tampered artefact
            # verifies clean today.
            if ($r.Status -eq 'HashMismatch') {
                $problems += ("$($r.What) has been MODIFIED since it was signed - the " +
                              "signature no longer matches the file ($($r.Path))")
            }
        }

        if ($ExpectTrusted -and -not $r.Trusted) {
            $problems += "$($r.What) chain is not trusted: $($r.Status)"
        }
    }

    # Say the specific thing rather than leaving whoever reads this to work it out. This exact
    # combination has one cause: something re-published the project between signing and the
    # MSI build.
    $msiOnly = ($results | Where-Object { $_.What -eq 'MSI' -and $_.Signed }) -and
               ($results | Where-Object { $_.What -eq 'Executable (inside MSI)' -and -not $_.Signed })
    if ($msiOnly) {
        $problems += ("The MSI is signed but the executable inside it is not. The MSI build " +
                      "overwrote the signed executable - pass -p:BuildProjectReferences=false " +
                      "to the wixproj build, or sign later in the sequence.")
    }

    if ($problems.Count -gt 0) {
        Write-Host ''
        foreach ($p in $problems) { Write-Host "FAIL: $p" }
        throw "Signature verification failed with $($problems.Count) problem(s)."
    }

    if (-not $ExpectTrusted) {
        Write-Host ''
        Write-Host ('NOTE: signatures are present and timestamped, but chain trust was NOT ' +
                    'required. Expected while signing with the SSL.com sandbox certificate. ' +
                    'Re-run with -ExpectTrusted once the real certificate is in use.')
    }

    Write-Host ''
    Write-Host 'Signature verification passed.'
}
finally {
    Remove-Item -LiteralPath $extractRoot -Recurse -Force -ErrorAction SilentlyContinue
}
