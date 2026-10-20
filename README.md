# OutGate

OutGate is a Windows outbound firewall monitor. It watches every connection your PC makes — per app, with destination, bytes and country — lets you decide allow / ask / block per app, publisher or path, and can enforce those decisions as real Windows Firewall rules.

It runs fully offline: traffic is captured with kernel ETW sessions, geolocation comes from a bundled offline database, and the world map uses bundled imagery (no tiles, no runtime network).

## Features

- Per-app live connection monitor: destinations, sent/received bytes, first-seen countries
- 2D and 3D offline world map of where your apps connect (bundled NASA Blue Marble / Natural Earth imagery)
- Allow / Ask / Block rules per app, publisher and exact path, with a review queue for new connections
- Optional enforcement as Windows Firewall rules — dry-run by default, never changes the default outbound policy
- Tray flyout with status, mode switch and today's numbers
- 5 themes (System, Light, Dark, Midnight, Aurora) with bundled OFL fonts
- CLI (`outboundctl`) and an MCP server so AI tools can query your network
- Pause / "network not working?" quick recovery (15-minute pause, turn off)

## Requirements

- Windows 10/11 (x64)
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) to build
- Administrator rights at runtime (real-time ETW kernel sessions and firewall rule management are admin-only)
- WebView2 Runtime for the map page (preinstalled on Windows 10/11)

## Build

```
dotnet build Outbound.sln
```

Run `src/Outbound.App\bin\Debug\net8.0-windows\Outbound.exe` as administrator.

Run the test suite (129 tests):

```
DOTNET_ROLL_FORWARD=LatestMajor dotnet test tests/Outbound.Tests/Outbound.Tests.csproj
```

## GeoIP database (not committed)

The city-level GeoIP database (~122 MB) is intentionally not in this repository. To enable country/city lookups:

1. Download the free **DB-IP City Lite** database (CC BY 4.0) from https://db-ip.com
2. Save it as `assets/geoip/dbip-city-lite.mmdb`

The app builds and runs without it — geolocation simply shows "?" for foreign IPs.

## Project layout

| Path | What |
|---|---|
| `src/Outbound.Core` | Engine: ETW capture, rules, policy, enforcement, GeoIP (pure .NET, unit-tested) |
| `src/Outbound.App` | WPF UI (Wpf.Ui 4.0), tray, map, named-pipe server |
| `src/outboundctl` | CLI client for the named pipe |
| `src/outbound-mcp` | MCP server exposing the monitor to AI tools |
| `tests/Outbound.Tests` | Unit tests for the core engine |

Note: the internal project and namespace name is `Outbound` / `OutboundWin`; the product name is **OutGate**.

## Data & privacy

Everything stays on your machine: rules in `%LOCALAPPDATA%\OutboundWin\rules.db`, settings in `%LOCALAPPDATA%\OutboundWin\settings.json`, logs in `%LOCALAPPDATA%\OutboundWin\`. No telemetry, no phone-home.

## License

[MIT](LICENSE)
