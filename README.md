# Arctic Offset Detector - Garry's Mod

A modern offset scanner for Garry's Mod with a clean ImGui interface.

## Features

- 🎯 Auto GMod process detection
- 🔍 Pattern-based memory scanning
- 🎨 Modern ImGui interface
- 📊 Real-time offset detection
- 💾 Export results as .INI or .H files
- ✅ Detects EntityList, LocalPlayer, and ViewMatrix offsets

## Requirements

- Windows 10/11
- Visual Studio 2019 or later
- DirectX 11
- Administrator privileges (for process memory access)

## Setup

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/arctic-offset-detector.git
cd arctic-offset-detector
```

### 2. Download ImGui
Run the setup script:
```bash
imgui_setup.bat
```

Or manually download ImGui:
1. Download ImGui from https://github.com/ocornut/imgui
2. Extract to `imgui/` folder in the project root

### 3. Build
1. Open `GModScanner.sln` in Visual Studio
2. Select `Release` configuration
3. Build Solution (Ctrl+Shift+B)
4. Run as Administrator

## Usage

1. Launch the scanner (run as Administrator)
2. Enable "Auto GMod Detection" to filter GMod processes
3. Select your Garry's Mod process
4. Choose a module (recommended: `client.dll` or `engine.dll`)
5. Click "START SCAN"
6. Export results using the buttons at the bottom

## Tips

- **LocalPlayer not found?** Make sure you're in-game, not in the menu
- **No processes shown?** Disable "Auto GMod Detection" to see all processes
- **Scan failed?** Try different modules (client.dll, engine.dll, or the .exe)
- **Run as Administrator** to access process memory

## Modules Guide

- `client.dll` - Best for EntityList and LocalPlayer
- `engine.dll` - Best for ViewMatrix
- `*.exe` - Main executable, contains some offsets

## Project Structure

```
├── GModScanner_GUI.cpp    # Main GUI application
├── GModScanner.cpp        # Console version (legacy)
├── imgui/                 # ImGui library (not included, download separately)
├── imgui_setup.bat        # Automatic ImGui setup script
└── IMGUI_SETUP.md         # ImGui setup instructions
```

## Building from Source

1. Ensure ImGui is installed in `imgui/` folder
2. Open `GModScanner.sln`
3. Project includes:
   - imgui.cpp
   - imgui_draw.cpp
   - imgui_tables.cpp
   - imgui_widgets.cpp
   - imgui_impl_win32.cpp
   - imgui_impl_dx11.cpp
4. Build and run

## Troubleshooting

### ImGui not found
- Run `imgui_setup.bat`
- Or manually download from https://github.com/ocornut/imgui

### Linking errors
- Make sure d3d11.lib is linked
- Check Windows SDK is installed
- Rebuild solution

### Access denied
- Run as Administrator
- Check antivirus isn't blocking

## Educational Purpose

This tool is for educational purposes only. Use responsibly and only on games you own.

## License

MIT License - See LICENSE file for details

## Credits

- ImGui by Omar Cornut
- Pattern scanning techniques from ArcticSoftwares
