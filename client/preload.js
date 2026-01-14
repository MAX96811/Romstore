const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    selectDir: () => ipcRenderer.invoke('select-dirs'),
    scanLocalEmulation: (baseDir) => ipcRenderer.invoke('scan-local-emulation', baseDir),
    downloadFile: (url, destPath, sessionToken) => ipcRenderer.invoke('download-file', { url, destPath, sessionToken }),
    checkLocalFile: (filePath) => ipcRenderer.invoke('check-local-file', filePath),
    getConfig: () => ipcRenderer.invoke('get-config'),
    saveConfig: (config) => ipcRenderer.invoke('save-config', config)
});
