# SentinelAI - Controlled Native Backend Startup Launcher
Set-Location "C:\Users\srisn\Desktop\Projects\sentinelai-complete\backend"

# 1. Target database override (explicit loopback)
$env:MONGO_URI = "mongodb://127.0.0.1:27017/sentinel-db"

Write-Host "=========================================================="
Write-Host "       SentinelAI - Controlled Native Backend Startup     "
Write-Host "=========================================================="
Write-Host ""
Write-Host "Target Database: mongodb://127.0.0.1:27017/sentinel-db"
Write-Host "Target Port:     http://127.0.0.1:5000"
Write-Host "Security Keys:   Loaded securely from backend/.env"
Write-Host ""
Write-Host "Starting SentinelAI Backend server..."
Write-Host "Keep this window open while using SentinelAI."
Write-Host "=========================================================="
Write-Host ""

npm start
