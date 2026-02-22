$ErrorActionPreference = "Stop"

function Test-Endpoint {
    param($Uri, $Method = "GET", $Body = $null)
    Write-Host "Testing $Method $Uri..."
    try {
        if ($Body) {
            $response = Invoke-WebRequest -Uri $Uri -Method $Method -Body $Body -ContentType "application/json"
        }
        else {
            $response = Invoke-WebRequest -Uri $Uri -Method $Method
        }
        Write-Host "Success: $($response.StatusCode)"
        Write-Host "Content: $($response.Content)"
    }
    catch {
        Write-Host "Error: $_"
    }
    Write-Host "----------------"
}

# 1. Check Status (Should be normal)
Test-Endpoint "http://127.0.0.1:5000/status"

# 2. Start Attack
Test-Endpoint "http://127.0.0.1:5000/start_attack"

# 3. Simulate Traffic (Generate some data)
Test-Endpoint "http://127.0.0.1:5000/simulate"

# 4. Check Status (Should show attack/traffic)
Test-Endpoint "http://127.0.0.1:5000/status"

# 5. Stop Attack
Test-Endpoint "http://127.0.0.1:5000/stop_attack"

# 6. Test Mitigation: Block IP
$blockBody = '{"ip": "10.0.0.5"}'
Test-Endpoint "http://127.0.0.1:5000/api/mitigate/block" "POST" $blockBody

# 7. Check Status (Should show blocked IP)
Test-Endpoint "http://127.0.0.1:5000/status"

# 8. Test Mitigation: Blackhole
$blackholeBody = '{"active": true}'
Test-Endpoint "http://127.0.0.1:5000/api/mitigate/blackhole" "POST" $blackholeBody

# 9. Test Mitigation: Scrubbing
$scrubbingBody = '{"active": true}'
Test-Endpoint "http://127.0.0.1:5000/api/mitigate/scrubbing" "POST" $scrubbingBody
