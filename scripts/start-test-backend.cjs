'use strict';
const path = require('path');
const dotenv = require('../backend/node_modules/dotenv');

const envTestPath = path.resolve(__dirname, '../backend/.env.test');
process.env.DOTENV_CONFIG_PATH = envTestPath;
dotenv.config({ path: envTestPath });

process.env.NODE_ENV = 'test';
process.env.START_SERVER = 'true';
process.env.CONTAINMENT_BACKEND = 'mock';
process.env.CONTAINMENT_DRY_RUN = 'true';
process.env.ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT = 'false';
process.env.ALLOW_TEST_ROUTES = 'true';

const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/sentinelai_test';
const dbName = mongoUri.split('/').pop().split('?')[0];
if (!dbName.toLowerCase().includes('test')) {
  console.error(`CRITICAL SAFETY ERROR: Test database "${dbName}" must contain "test"! Refusing to start.`);
  process.exit(1);
}

process.chdir(path.resolve(__dirname, '../backend'));
require('../backend/server.js');
