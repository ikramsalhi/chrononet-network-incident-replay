# Push ChronoNet to GitHub — Windows PowerShell

Use these commands after you create an **empty** GitHub repository named `chrononet-network-incident-replay`.

> Important: when GitHub creates the repository, **do not** add a README, `.gitignore`, or license there. This project already contains them.

## 1. Open PowerShell in the project folder

```powershell
cd C:\Users\Lenovo\Downloads\chrononet-network-incident-replay
```

## 2. Make sure Git is available

```powershell
git --version
```

If PowerShell says Git is not recognized but Git is installed:

```powershell
$env:Path += ";C:\Program Files\Git\cmd"
git --version
```

## 3. Test the project before the first commit

```powershell
py -m unittest discover -s tests -v
```

Expected result: all tests end in `OK`.

## 4. Initialize Git and commit

```powershell
git init
git branch -M main
git add .
git status
git commit -m "Initial release: ChronoNet incident replay workbench"
```

## 5. Connect your GitHub repository

Replace `YOUR_GITHUB_USERNAME` with your GitHub username:

```powershell
git remote add origin https://github.com/YOUR_GITHUB_USERNAME/chrononet-network-incident-replay.git
git remote -v
git push -u origin main
```

If `origin` already exists:

```powershell
git remote set-url origin https://github.com/YOUR_GITHUB_USERNAME/chrononet-network-incident-replay.git
git push -u origin main
```

## 6. For later updates

```powershell
git status
git add .
git commit -m "Describe the update"
git push
```

## Repository description

`Explainable network incident replay, symptom correlation, blast-radius analysis and root-cause reporting.`

## Recommended topics

`networking` `cybersecurity` `network-forensics` `incident-response` `python` `observability` `root-cause-analysis` `systems`
