const { app, BrowserWindow } = require('electron');
const { exec } = require('child_process');
const path = require('path');

let mainWindow;

function createWindow() {

    // 🔥 Start backend (hidden, no extra CMD)
    exec(`python "${path.join(__dirname, 'app.py')}"`);

    // wait for server
    setTimeout(() => {
        mainWindow = new BrowserWindow({
            width: 1200,
            height: 800
        });

        mainWindow.loadURL('http://127.0.0.1:5000');
    }, 4000);
}

app.whenReady().then(createWindow);