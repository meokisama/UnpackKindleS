call "HandleAZW3"
cd /d %~dp0\app
UnpackKindleS "%USERPROFILE%\OneDrive - MSFT\Documents\My Kindle Content" .. -dedrm -batch --rename-xhtml-with-id
pause