<#
This creates and dumps a certificate chain based on a PFX file

Creates

- public key (.crt)
- intermediate CA (.intermediate_n.crt)
- root CA, (.root.crt)
- trusted chain (.trustedchain.crt) - all intermediates and root
- full chain (.chain.crt) - public key, intermediates, and root

Use cases:

- Export-PFXCertificateChainInteractive

# $path = 'C:\PFX\Cert.pfx'
- Export-PFXCertificateChain -Path $path

# $password = (ConvertTo-SecureString 'password' -AsPlainText -Force)
- Export-PFXCertificateChain -Path $path -Password $password
- Export-PFXCertificateChain -Path $path -Password $password -Destination 'C:\OutputFolder'
- Export-PFXCertificateChain -Path $path -Password $password -ExportType Public
- Export-PFXCertificateChain -Path $path -Password $password -ExportType Intermediate
- Export-PFXCertificateChain -Path $path -Password $password -ExportType Root
- Export-PFXCertificateChain -Path $path -Password $password -ExportType TrustedChain
- Export-PFXCertificateChain -Path $path -Password $password -ExportType FullChain
- Export-PFXCertificateChain -Path $path -Password $password -ExportType Public,Intermediate,Root

#>

class ExportCertChain {

    [string]$Path
    [SecureString]$Password
    [string]$Destination

    hidden [System.Security.Cryptography.X509Certificates.X509Chain]$Chain
    hidden [System.IO.FileInfo]$PfxFile
    hidden [string]$PublicCert
    hidden [System.Collections.Generic.List[string]]$IntermediateCerts = @()
    hidden [string]$RootCert

    ExportCertChain([string]$Path, [string]$Destination) {
        $this.Path = $Path
        $this.Destination = $Destination
        $this.LoadCertificate()
    }

    ExportCertChain([string]$Path, [SecureString]$Password, [string]$Destination) {
        $this.Path = $Path
        $this.Password = $Password
        $this.Destination = $Destination
        $this.LoadCertificate()
    }

    hidden [void]LoadCertificate() {
        $this.PfxFile = New-Object System.IO.FileInfo $this.Path

        if(-not $this.PfxFile.Exists) {
            Write-Warning "File does not exist"
            return
        }

        $certificate = if($null -eq $this.Password) {
            New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $this.PfxFile.FullName
        }
        else {
            New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $this.PfxFile.FullName, $this.Password
        }

        $this.Chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    
        if(-not $this.Chain.Build($certificate)) {
            throw "Unable to build certificate chain"
        }
    
        if($this.Chain.ChainElements.Count -eq 0) {
            throw "No certificates in chain"
        }
        
        $this.PublicCert = $this.GetCrtSnip($this.Chain.ChainElements[0].Certificate)
        
        for($i = 1; $i -lt $this.Chain.ChainElements.Count-1; $i++) {
            $intCrt = $this.GetCrtSnip($this.Chain.ChainElements[$i].Certificate)
            $this.IntermediateCerts.Add($intCrt)
        }

        $this.RootCert = $this.GetCrtSnip($this.Chain.ChainElements[-1].Certificate)
    }

    hidden [string]GetCrtSnip([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) {
        return @"
-----BEGIN PUBLIC KEY-----
{0}
-----END PUBLIC KEY-----
"@ -f [System.Convert]::ToBase64String($Certificate.RawData)
    }
    
    hidden [string]GetCrtPath([string]$Extension) {   
        return Join-Path -Path $this.Destination -ChildPath $this.PfxFile.Name.Replace('.pfx', $Extension)
    }

    [void]ExportAll() {
        $this.ExportPublicCert()
        $this.ExportIntermediateCerts()
        $this.ExportRootCert()
        $this.ExportTrustedChain()
        $this.ExportFullChain()
    }

    [void]ExportPublicCert() {
        $crtPath = $this.GetCrtPath('.crt')
        $this.PublicCert | Set-Content -Path $crtPath
        Write-Verbose "Exported public key to $crtPath"
    }

    [void]ExportIntermediateCerts() {
        for($i = 0; $i -lt $this.IntermediateCerts.Count; $i++) {
            $crtPath = $this.GetCrtPath(".intermediate_$i.crt")
            $this.IntermediateCerts[$i] | Set-Content -Path $crtPath
            Write-Verbose "Exported intermediate $i crt to $crtPath"
        }
    }

    [void]ExportRootCert() {
        $crtPath = $this.GetCrtPath('.root.crt')
        $this.RootCert | Set-Content -Path $crtPath
        Write-Verbose "Exported root crt to $crtPath"
    }

    [void]ExportTrustedChain() {
        $crtPath = $this.GetCrtPath('.trustedchain.crt')
        $this.IntermediateCerts, $this.RootCert | Set-Content -Path $crtPath
        Write-Verbose "Exported trusted chain to $crtPath"
    }

    [void]ExportFullChain() {
        $crtPath = $this.GetCrtPath('.chain.crt')
        $this.PublicCert, $this.IntermediateCerts, $this.RootCert | Set-Content -Path $crtPath
        Write-Verbose "Exported full chain to $crtPath"
    }
}

function Export-PFXCertificateChainInteractive {
    
    Add-Type -AssemblyName 'System.Windows.Forms'

    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = 'PFX|*.pfx'
    $dialog.Multiselect = $false
    
    $result = $dialog.ShowDialog()
    
    if($result -ne [System.Windows.Forms.DialogResult]::OK) {
        Write-Warning "Cancelled due to user request"
        return
    }
    
    $password = Read-Host "Certificate password" -AsSecureString
    $destination = Read-Host "Output directory (empty = same as input)"

    Export-PFXCertificateChain -Path $dialog.FileName -Password $password -Destination $destination
}

function Export-PFXCertificateChain 
{
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        
        [SecureString]$Password = $null,

        [string]$Destination = $null,

        [ValidateSet('All', 'Public', 'Intermediate', 'Root', 'TrustedChain', 'FullChain')]
        [string[]]$ExportType = 'All'
    )

    if([string]::IsNullOrWhiteSpace($Destination)) {
        $Destination = [System.IO.Path]::GetDirectoryName($Path)
    }

    try {
        $chain = if($null -ne $Password -and $Password.Length -gt 0) {
            [ExportCertChain]::new($Path, $Password, $Destination)
        }
        else {
            [ExportCertChain]::new($Path, $Destination)
        }

        switch($ExportType) {
            'All' {
                $chain.ExportAll()
            }
            'Public' {
                $chain.ExportPublicCert()
            }
            'Intermediate' {
                $chain.ExportIntermediateCerts()
            }
            'Root' {
                $chain.ExportRootCert()
            }
            'TrustedChain' {
                $chain.ExportTrustedChain()
            }
            'FullChain' {
                $chain.ExportFullChain()
            }
        }
    }
    catch {
        Write-Error $_
    }
}


