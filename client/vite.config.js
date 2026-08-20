import { resolve } from 'path';
import { defineConfig } from 'vite';
import fs from 'fs';

function copyDir(src, dest) {
    if (!fs.existsSync(src)) return;
    fs.mkdirSync(dest, { recursive: true });
    const entries = fs.readdirSync(src, { withFileTypes: true });
    for (const entry of entries) {
        const srcPath = resolve(src, entry.name);
        const destPath = resolve(dest, entry.name);
        if (entry.isDirectory()) {
            copyDir(srcPath, destPath);
        } else {
            fs.copyFileSync(srcPath, destPath);
        }
    }
}

export default defineConfig({
    base: './',
    build: {
        outDir: 'dist',
        rollupOptions: {
            input: {
                main: resolve(__dirname, 'index.html'),
                dashboard: resolve(__dirname, 'dashboard.html'),
                musicPlayer: resolve(__dirname, 'music-player.html'),
                aiAssistant: resolve(__dirname, 'ai-assistant.html'),
                sessions: resolve(__dirname, 'sessions.html'),
                register: resolve(__dirname, 'register.html'),
                forgotPassword: resolve(__dirname, 'forgot-password.html'),
                resetPassword: resolve(__dirname, 'reset-password.html')
            }
        }
    },
    plugins: [
        {
            name: 'copy-static-js-css',
            closeBundle() {
                copyDir(resolve(__dirname, 'js'), resolve(__dirname, 'dist/js'));
                copyDir(resolve(__dirname, 'css'), resolve(__dirname, 'dist/css'));
            }
        }
    ]
});
