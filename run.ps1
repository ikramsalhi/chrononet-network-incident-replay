Set-Location $PSScriptRoot
if (Get-Command py -ErrorAction SilentlyContinue) {
    py app.py
} else {
    python app.py
}
