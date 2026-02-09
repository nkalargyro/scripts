# Scripts

Personal utility scripts for Windows.

## Organize-Files.ps1

Sorts files from `~/Downloads` into categorized subfolders under `~/Organized`.

### Categories

| Folder | Extensions |
|---|---|
| Documents | .pdf, .docx, .doc, .xlsx, .xls, .pptx, .csv, .txt, .rtf |
| Images | .png, .jpg, .jpeg, .gif, .bmp, .svg, .webp, .ico |
| Videos | .mp4, .avi, .mkv, .mov, .wmv |
| Installers | .exe, .msi |
| Archives | .zip, .rar, .7z, .tar, .gz |
| Other | Everything else |

### Usage

```powershell
# Preview what would be moved (dry-run)
.\Organize-Files.ps1

# Actually move the files
.\Organize-Files.ps1 -Confirm

# Include subfolders in Downloads
.\Organize-Files.ps1 -Recurse -Confirm
```

### Safety

- Dry-run by default — nothing moves unless you pass `-Confirm`
- Handles duplicate filenames by appending `(1)`, `(2)`, etc.
- Skips system files (`desktop.ini`, `thumbs.db`, `ntuser*`)
- Logs all moves to `~/Organized/organize-log.txt`
