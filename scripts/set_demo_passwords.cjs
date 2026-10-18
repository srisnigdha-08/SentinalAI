const path = require('path')
require(path.join(__dirname, '..', 'backend', 'node_modules', 'dotenv')).config({ path: path.join(__dirname, '..', 'backend', '.env') })
const mongoose = require(path.join(__dirname, '..', 'backend', 'node_modules', 'mongoose'))
const bcrypt = require(path.join(__dirname, '..', 'backend', 'node_modules', 'bcryptjs'))
const User = require(path.join(__dirname, '..', 'backend', 'models', 'User'))

async function run() {
  await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/sentinel-db')
  const pAdmin = await bcrypt.hash('Admin@1234', 12)
  const pAnalyst = await bcrypt.hash('Analyst@1234', 12)
  const pViewer = await bcrypt.hash('Viewer@1234', 12)

  await User.updateOne({ email: 'admin@sentinel.io' }, { $set: { password: pAdmin, status: 'active', mustChangePassword: false } })
  await User.updateOne({ email: 'arjun@sentinel.io' }, { $set: { password: pAnalyst, status: 'active', mustChangePassword: false } })
  await User.updateOne({ email: 'sara@sentinel.io' }, { $set: { password: pViewer, status: 'active', mustChangePassword: false } })

  console.log('Demo user passwords set successfully!')
  await mongoose.disconnect()
}

run().catch(err => {
  console.error(err)
  process.exit(1)
})
