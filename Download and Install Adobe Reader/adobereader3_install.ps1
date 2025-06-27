#Changes to C Directory
cd C:\
 
#Download link for Adobe Offline Installer
$url = "https://ardownload2.adobe.com/pub/adobe/reader/win/AcrobatDC/2400220965/AcroRdrDC2400220965_en_US.exe"
 
#Download path for Adobe
$outpath = "C:\Temp\AcroRdrDC2400220965_en_US.exe"
 
#Configuration of DL
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($url, $outpath)
 
#Allows for download of Adobe to occur
Start-Sleep -s 20
 
#Changes to C Directory
cd C:\temp
 
#Installs Adobe
Start-process AcroRdrDC2400220965_en_US.exe -ArgumentList "/sPB /rs"
 
#Allows for Adobe to Install
Start-Sleep -s 60
 
#Removes Adobe Installation Media. 
rm -Force C:\Temp\AcroRdrDC2400220965_en_US.exe
