
Write-Host "Starting DDoS Mitigation System..."

# Start Backend Server
Start-Process "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -ArgumentList "backend/server.py" -WorkingDirectory "$PSScriptRoot" -WindowStyle Normal
Write-Host "Backend Server started (New Window)."

# Start Legitimate Traffic Simulation
Start-Process "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -ArgumentList "simulation/legit_traffic.py" -WorkingDirectory "$PSScriptRoot" -WindowStyle Minimized
Write-Host "Legitimate Traffic Simulation started (Minimized)."

Write-Host "---------------------------------------------------"
Write-Host "Dashboard available at: http://127.0.0.1:5000"
Write-Host "To simulate an attack, run: python simulation/attack_traffic.py"
Write-Host "---------------------------------------------------"
