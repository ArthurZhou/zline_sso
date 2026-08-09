import { defineConfig } from 'vite';
import { resolve } from 'path';
import { fileURLToPath } from 'url';
import { viteStaticCopy } from 'vite-plugin-static-copy';
import ViteMinifyPlugin from 'vite-plugin-html-minifier-terser';

const __dirname = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  base: './',
  plugins: [
    // If the error persists, try: (ViteMinifyPlugin as any)({ ... }) 
    // or import ViteMinifyPlugin from '...' (without braces)
    ViteMinifyPlugin({
      removeComments: true,
      collapseWhitespace: true,
      minifyJS: true,
      minifyCSS: true,
    }),
    viteStaticCopy({
      targets: [
        {
          src: 'AGREEMENT.md',
          dest: './' 
        }
      ]
    })
  ],
  build: {
    outDir: '../static',
    emptyOutDir: true,
    minify: 'esbuild',
    rollupOptions: {
      input: {
        login: resolve(__dirname, 'login.html'),
        continue: resolve(__dirname, 'continue.html'),
        agreement: resolve(__dirname, 'agreement.html'),
        profile: resolve(__dirname, 'profile.html'),
        admin: resolve(__dirname, 'admin.html'),
      },
    },
  },
});