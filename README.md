# RomStore

**RomStore** is a self-hosted game library manager and save synchronization system. It consists of a Dockerized Node.js backend, an Nginx frontend, and a cross-platform Electron desktop client.

## Features

*   **Centralized Library**: Host your ROMs, BIOS files, and Save data on your own server.
*   **Save Synchronization**: "Steam-like" save syncing with conflict detection (Cloud vs Local) and version history.
*   **Metadata**: Automatically fetches game artwork and metadata (via IGDB).
*   **Secure Auth**: Session-based authentication for multiple users.
*   **Cross-Platform Client**: Electron app for Windows and Linux (AppImage).

## Architecture

*   **Backend**: Node.js (Express), SQLite (via file system/JSON), Dockerized.
*   **Frontend (Web)**: Nginx serving static assets (legacy/admin panel).
*   **Client**: Electron (Node.js + Chromium) with `chokidar` for file watching.
*   **Data**: Stored in `./data` (User DB) and `/emulation` (ROMS/BIOS/Saves).

## Prerequisites

*   **Docker & Docker Compose**: For running the server.
*   **Node.js (v18+) & NPM**: For running/building the client.
*   **Git**: For version control.

## 🚀 Getting Started

### 1. Server Setup (Docker)

The server runs in Docker containers to ensure consistency and easy deployment.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/MAX96811/Romstore.git
    cd Romstore
    ```

2.  **Start the Server:**
    ```bash
    docker-compose up --build -d
    ```
    *   **Backend API**: `http://localhost:3000`
    *   **Web Frontend**: `http://localhost:1567`
    *   **Data Persistence**: Data is stored in `./data` and your mapped emulation folders.

### 2. Client Setup (Desktop App)

The client is an Electron app that connects to your server.

1.  **Navigate to the client directory:**
    ```bash
    cd client
    ```

2.  **Install Dependencies:**
    ```bash
    npm install
    ```

3.  **Run the Client:**
    ```bash
    npm start
    ```

## 🛠️ Configuration

### Server Configuration
*   **Ports**: Defined in `docker-compose.yml`.
*   **Storage**: 
    *   `/emulation/roms`
    *   `/emulation/saves`
    *   `/emulation/bios`
    *   *Note: Modify `docker-compose.yml` volumes to map these to your host folders if needed.*

### Client Configuration
*   **Settings**: Click the "Settings" gear icon in the app.
*   **Server URL**: Enter your server address (e.g., `http://localhost:3000` or your LAN IP).
*   **Local Directory**: Point this to your local emulation folder (e.g., `C:\Emulation` or `/home/deck/Emulation`).

## 📦 Building & Deployment

### Server (Docker Image)
To rebuild the server image (e.g., after code changes or for optimization):
```bash
# Rebuild and restart in background
docker-compose up --build -d
```
*   *Optimization*: The `dockerfile` uses `node:20-alpine` and `.dockerignore` to keep image sizes small (<150MB).

### Client (Executables)
To build the desktop application for distribution:

**Windows (.exe):**
```bash
cd client
npm run dist:win
```
*   Output: `client/dist/RomStore Setup <version>.exe`

**Linux (.AppImage):**
*   *Note: Must be built on Linux or WSL (Windows Subsystem for Linux).*
```bash
cd client
npm run dist:linux
```
*   Output: `client/dist/RomStore-<version>.AppImage`

## 🔄 Save Synchronization Logic
The client uses a smart sync system:
1.  **Watcher**: Monitors your local save directory for changes.
2.  **Debounce**: Waits 1 second after writing stops to prevent partial uploads.
3.  **Conflict Detection**:
    *   **Safe Upload**: Local changed, Server unchanged → Auto-Upload.
    *   **Safe Download**: Server changed, Local unchanged → Auto-Download.
    *   **Conflict**: Both changed since last sync → **User Prompt** (Keep Local vs Keep Cloud).

## 📝 Developer Notes
*   **Logs**:
    *   Server: `docker-compose logs -f`
    *   Client: Check the VS Code terminal or DevTools Console (Ctrl+Shift+I).
*   **Ignore Files**:
    *   `.dockerignore`: Excludes `client/`, `.git/`, `node_modules/` from Docker builds.
    *   `.gitignore`: Standard Node.js excludes.

---
*Maintained by Maxime*