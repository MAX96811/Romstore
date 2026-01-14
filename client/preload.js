const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    selectDir: () => ipcRenderer.invoke('select-dirs'),
    scanLocalEmulation: (baseDir) => ipcRenderer.invoke('scan-local-emulation', baseDir),
    scanDirStat: (baseDir) => ipcRenderer.invoke('scan-dir-stat', baseDir),
    downloadFile: (url, destPath, sessionToken, relPath) => ipcRenderer.invoke('download-file', { url, destPath, sessionToken, relPath }),
    deleteFile: (filePath) => ipcRenderer.invoke('delete-file', filePath),
    backupLocalFile: (filePath) => ipcRenderer.invoke('backup-local-file', filePath),
    checkLocalFile: (filePath) => ipcRenderer.invoke('check-local-file', filePath),
    getConfig: () => ipcRenderer.invoke('get-config'),
    saveConfig: (config) => ipcRenderer.invoke('save-config', config),
    onDownloadProgress: (callback) => ipcRenderer.on('download-progress', callback),
    
    // Save Sync
    startSaveWatcher: (saveDir) => ipcRenderer.invoke('start-save-watcher', saveDir),
    stopSaveWatcher: () => ipcRenderer.invoke('stop-save-watcher'),
    uploadSave: (filePath, relPath, sessionToken) => ipcRenderer.invoke('upload-save', { filePath, relPath, sessionToken }),
    onSaveChange: (callback) => ipcRenderer.on('save-change', callback),
    
    // Version Control
    getSaveVersions: (relPath) => ipcRenderer.invoke('get-save-versions', relPath),
    restoreSaveVersion: (relPath, versionName) => ipcRenderer.invoke('restore-save-version', { relPath, versionName })
});
