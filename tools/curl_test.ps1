# Ground truth for the Phase 1 live test: curl's own PID + its view of remote IP/port and bytes.
param([string]$Url = "https://example.com")
$out = Join-Path $env:TEMP "outbound_curl_out.txt"
$fmt = 'remote_ip=%{remote_ip} remote_port=%{remote_port} size_request=%{size_request} size_upload=%{size_upload} size_header=%{size_header} size_download=%{size_download} http=%{http_code}'
$p = Start-Process "$env:SystemRoot\System32\curl.exe" -ArgumentList "-s -o NUL -w `"$fmt`" $Url" -PassThru -NoNewWindow -RedirectStandardOutput $out
$p.WaitForExit()
"curl_pid=$($p.Id) exit=$($p.ExitCode)"
Get-Content $out
