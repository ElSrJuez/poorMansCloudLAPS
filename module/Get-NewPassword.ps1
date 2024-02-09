#===============================================================================
function Get-NewPassword($passwordLength){ #minimum 10 characters will always be returned
    $password = Get-RandomCharacters -length ([Math]::Max($passwordLength-6,4)) -characters 'abcdefghikmnoprstuvwxyz'
    $password += Get-RandomCharacters -length 2 -characters 'ABCDEFGHKLMNPRSTUVWXYZ'
    $password += Get-RandomCharacters -length 2 -characters '23456789'
    $password += Get-RandomCharacters -length 2 -characters '!_%&/()=?}][{#*+'
    $characterArray = $password.ToCharArray()   
    $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
    $outputString = -join $scrambledStringArray
    return $outputString 
}
