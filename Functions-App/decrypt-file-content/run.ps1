#***********************************************************************************************
#-- Purpose: This Azure function package contains process to decrypt the file content 
#
#-- MODIFICATION HISTORY
#-- Changed by         Changed Date    Change description
#-- ------------------ ------------    ---------------------------------------------------------
#-- Parameswaran S N   12/11/2019      Initial version v0.1
#***********************************************************************************************

#Import namespace
using namespace System.Net
using namespace System.Security.Cryptography
using namespace System.Text.Encoding
using namespace System.Convert

# Input bindings are passed in via param block
    param($Request, $TriggerMetadata)

# Interact with query parameters or the body of the request
#$Mode     = $Request.Body.Mode
$Key      = $Request.Body.Key
$FilePath = $Request.Body.FilePath

#Assigning encryption properties - AES-CBC-256 using $Key
    $shaManaged           = New-Object System.Security.Cryptography.SHA256Managed
    $aesManaged           = New-Object System.Security.Cryptography.AesManaged
    $aesManaged.Mode      = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding   = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize   = 256
    $aesManaged.Key       = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

# Write to the Azure Functions log stream
Write-Host "PowerShell HTTP trigger function processed a request."

# Check for filecontent and start encryption process
    if ($FilePath) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($FilePath)}

        $encryptor = $aesManaged.CreateEncryptor()
        $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
        $encryptedBytes = $aesManaged.IV + $encryptedBytes
        
        $encryptstring =  [System.Convert]::ToBase64String($encryptedBytes)
        
    #if ($FilePath) {return [System.Convert]::ToBase64String($encryptedBytes)}  

    #return [System.Convert]::ToBase64String($encryptedBytes)

        #------------
        #--Decryption
        #-------------
        $cipherBytes = [System.Convert]::FromBase64String($FilePath)
        $aesManaged.IV = $cipherBytes[0..15]
        $decryptor = $aesManaged.CreateDecryptor()
        $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
        
        #$dencryptstring =  [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)
        $dencryptstring =  [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)
                    
#Function output
if ($FilePath) {
    $status = [HttpStatusCode]::OK
    $body = "$dencryptstring"
}

else {
    $status = [HttpStatusCode]::BadRequest
    $body = "Check input and output bindings for the function."
}

$shaManaged.Dispose()
$aesManaged.Dispose()

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $status
    Body = $body
})