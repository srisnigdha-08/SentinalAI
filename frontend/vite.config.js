import{defineConfig}from 'vite';import react from '@vitejs/plugin-react'
const target = process.env.SENTINEL_DEV_API_PROXY || 'http://127.0.0.1:5000'
export default defineConfig({plugins:[react()],server:{port:3000,proxy:{'/api':{target,changeOrigin:true},'/socket.io':{target,ws:true}}}})
