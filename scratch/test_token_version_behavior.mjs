import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const mongoose = require('../backend/node_modules/mongoose');
const jwt = require('../backend/node_modules/jsonwebtoken');
const auth = require('../backend/services/authSessionService');
const User = require('../backend/models/User');
const AuthSession = require('../backend/models/AuthSession');

async function testTokenVersionMissing() {
  process.env.JWT_SECRET = 'test-access-secret-32-chars-long!!';
  process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-32-chars-long!!';

  await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db-test-tv');
  const db = mongoose.connection.db;

  // Create a user document directly without tokenVersion (simulating admin@sentinel.local)
  const testUser = {
    _id: new mongoose.Types.ObjectId(),
    email: 'test_no_tv@sentinel.local',
    name: 'No Token Version User',
    password: 'hashedpassworddummy',
    role: 'admin',
    status: 'active',
    authVersion: 0,
    // tokenVersion is intentionally omitted (undefined)
  };
  await db.collection('users').insertOne(testUser);

  console.log('=== TEST 1: User loaded from DB ===');
  const loadedUser = await User.findById(testUser._id);
  console.log('loadedUser.authVersion:', loadedUser.authVersion);
  console.log('loadedUser.tokenVersion (in document):', loadedUser.tokenVersion);
  console.log('loadedUser.toJSON().tokenVersion:', loadedUser.toJSON().tokenVersion);

  console.log('\n=== TEST 2: Issue Session for User ===');
  const issued = await auth.issue(loadedUser);
  console.log('Issued accessToken successfully:', Boolean(issued.token));
  console.log('Issued refreshToken successfully:', Boolean(issued.refreshToken));

  console.log('\n=== TEST 3: Authorize accessToken (protect middleware path) ===');
  const authResult = await auth.authorize(issued.token);
  console.log('Authorize passed:', Boolean(authResult.user && authResult.session));

  console.log('\n=== TEST 4: Rotate refreshToken ===');
  const rotateResult = await auth.rotate(issued.refreshToken);
  console.log('Rotate passed:', Boolean(rotateResult.token && rotateResult.refreshToken));

  await db.dropDatabase();
  await mongoose.disconnect();
}

testTokenVersionMissing().catch(console.error);
