import{defineConfig}from 'vite';import react from '@vitejs/plugin-react'
import { CONTENT_SECURITY_POLICY } from './csp.js'
const target = process.env.SENTINEL_DEV_API_PROXY || 'http://127.0.0.1:5000'
const proxy = {'/api':{target,changeOrigin:true},'/socket.io':{target,ws:true}}
export default defineConfig({plugins:[react()],server:{port:3000,proxy,warmup:{clientFiles:['./src/pages/*.jsx','./src/components/*.jsx']}},preview:{port:4173,proxy,headers:{'Content-Security-Policy':CONTENT_SECURITY_POLICY}}})
