$issuer = (echo "" | openssl s_client -connect www.cse.iitb.ac.in:443 2>$null | openssl x509 -noout -issuer)
$cn = [regex]::Match($issuer,'CN=([^,\/]+(?: [^,\/]+)*)').Groups[1].Value.Trim()
$flag = "cs409m{$($cn -replace ' ', '_')}".ToLower()
Write-Output $flag