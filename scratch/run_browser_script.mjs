import { spawn } from 'child_process';
import path from 'path';

const script = process.argv[2];
if (!script) {
  console.error('Usage: node scratch/run_browser_script.mjs <script-path>');
  process.exit(1);
}

const env = {
  ...process.env,
  VERIFY_ADMIN_PASSWORD: 'Admin@1234',
  VERIFY_ANALYST_PASSWORD: 'Analyst@1234',
  VERIFY_VIEWER_PASSWORD: 'Viewer@1234',
  HONEYPOT_API_KEY: 'b09b49ab1eeff33d1b0fa5f7f721e6d5ea60b0a1c430fec8d00813f13b5ff94e',
  MONGO_URI: 'mongodb://localhost:27017/sentinel-db',
  DOTENV_CONFIG_PATH: 'c:\\Users\\srisn\\Desktop\\Projects\\sentinelai-complete\\deployment\\.env.demo'
};

const proc = spawn('node', [script], {
  env,
  stdio: 'inherit'
});

proc.on('close', (code) => {
  console.log(`\n--- SCRIPT EXITED WITH CODE: ${code} ---`);
  process.exit(code || 0);
});
