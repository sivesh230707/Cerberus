# =========================================================
# Cerberus Test Payload: Suspicious / Policy Violation Demo
# Triggers:
# 1. Sensitive Path Access: C:\Windows\System32\config\SAM
# 2. Unauthorized Child Process Spawn: cmd.exe /c whoami /priv
# 3. Outbound Network Connection Attempt: 198.51.100.42:443
# =========================================================

Write-Output "[+] Payload initialized. Commencing unauthorized operations..."

# 1. Sensitive path read
Write-Output "[*] Probing Windows Credential Hive..."
try {
    [System.IO.File]::ReadAllBytes("C:\Windows\System32\config\SAM")
} catch {
    Write-Output "[-] Read attempt recorded: $($_.Exception.Message)"
}

# 2. Child process execution
Write-Output "[*] Spawning reconnaissance child process..."
Start-Process -FilePath "cmd.exe" -ArgumentList "/c whoami /priv" -NoNewWindow -Wait

# 3. Outbound network connect
Write-Output "[*] Attempting outbound beacon to C2 server (198.51.100.42:443)..."
try {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect("198.51.100.42", 443)
} catch {
    Write-Output "[-] Connection attempt recorded."
}

Write-Output "[+] Payload execution cycle complete."
