[CmdletBinding()]
param(
    [int]$Port = $(if ($env:APP_PORT) { [int]$env:APP_PORT } else { 8000 })
)

$ErrorActionPreference = "Stop"
$taskName = "NetMon Server"

function Test-NetMonHealthy {
    param([int]$HealthPort)

    try {
        # /healthz is deliberately protected by the app middleware. A 303 to
        # /login proves the FastAPI process is accepting and handling requests.
        $request = [Net.HttpWebRequest]::Create("http://127.0.0.1:$HealthPort/healthz")
        $request.AllowAutoRedirect = $false
        $request.Timeout = 5000
        $response = $request.GetResponse()
        try {
            return [int]$response.StatusCode -eq 303 -and
                $response.Headers["Location"] -eq "/login"
        }
        finally {
            $response.Dispose()
        }
    }
    catch [Net.WebException] {
        if ($_.Exception.Response) {
            try {
                $response = $_.Exception.Response
                return [int]$response.StatusCode -eq 303 -and
                    $response.Headers["Location"] -eq "/login"
            }
            finally {
                $_.Exception.Response.Dispose()
            }
        }
        return $false
    }
    catch {
        return $false
    }
}

if (Test-NetMonHealthy -HealthPort $Port) {
    exit 0
}

try {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if ($task.State -eq "Running") {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop
        Start-Sleep -Seconds 2
    }
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
}
catch {
    Write-Error "NetMon watchdog could not restart '$taskName': $($_.Exception.Message)"
    exit 1
}
