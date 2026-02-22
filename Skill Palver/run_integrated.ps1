
Write-Host "Starting DDoS Mitigation System (Integrated Mode)..."

# Start Backend Server (which now handles traffic generation)
Start-Process "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -ArgumentList "backend/server.py" -WorkingDirectory "$PSScriptRoot" -WindowStyle Normal
Write-Host "Backend Server started."

Write-Host "---------------------------------------------------"
Write-Host "Dashboard available at: http://127.0.0.1:5000"
Write-Host "Use the 'Start Attack' button on the dashboard to simulate DDoS."
Write-Host "---------------------------------------------------"
