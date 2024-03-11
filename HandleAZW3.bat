@echo off
setlocal enabledelayedexpansion

set "parent_folder=C:\Users\hoang\OneDrive - MSFT\Documents\My Kindle Content"

for /d %%A in ("%parent_folder%\*") do (
    if /i not "%%~nxA"=="NoteDocuments" (
        for %%B in ("%%A\*.azw") do (
            set "file=%%B"
            calibredb add "!file!" > temp.txt
            for /f "tokens=* USEBACKQ" %%F in (temp.txt) do (
                set "output=%%F"
            )
            del temp.txt
            for /f "tokens=4" %%N in ("!output!") do (
                calibredb export "%%N" --dont-asciiize --dont-save-cover --dont-save-extra-files --dont-update-metadata --dont-write-opf --template "{title}" --formats azw3 --to-dir "%%A"
            )
            calibredb remove "%%N" --permanent
        )
    )
)