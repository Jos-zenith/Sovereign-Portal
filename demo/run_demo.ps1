Write-Host "VICT Demo Flow" -ForegroundColor Cyan
Write-Host "1) Scan" -ForegroundColor Yellow
python src/vict_cli.py scan demo/sample_function.py
Write-Host "`n2) Wrap" -ForegroundColor Yellow
python src/vict_cli.py wrap demo/sample_function.py --out dist
Write-Host "`n3) Deploy" -ForegroundColor Yellow
python src/vict_cli.py deploy --region ap-south-1 --workspace .
Write-Host "`nOpen dashboard:" -ForegroundColor Green
Write-Host "demo/portal/index.html"
