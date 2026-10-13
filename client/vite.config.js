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
                main: resolve(import.meta.dirname, 'index.html'),
                dashboard: resolve(import.meta.dirname, 'dashboard.html'),
                musicPlayer: resolve(import.meta.dirname, 'music-player.html'),
                aiAssistant: resolve(import.meta.dirname, 'ai-assistant.html'),
                sessions: resolve(import.meta.dirname, 'sessions.html'),
                register: resolve(import.meta.dirname, 'register.html'),
                forgotPassword: resolve(import.meta.dirname, 'forgot-password.html'),
                resetPassword: resolve(import.meta.dirname, 'reset-password.html')
            }
        }
    },
    plugins: [
        {
            name: 'copy-static-js-css',
            closeBundle() {
                copyDir(resolve(import.meta.dirname, 'js'), resolve(import.meta.dirname, 'dist/js'));
                copyDir(resolve(import.meta.dirname, 'css'), resolve(import.meta.dirname, 'dist/css'));
            }
        }
    ]
});
