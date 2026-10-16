const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const UserSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, minlength: 2, maxlength: 50 },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true, minlength: 8, select: false },
    role: { type: String, enum: ['admin', 'analyst', 'viewer'], default: 'viewer' },
    status: { type: String, enum: ['active', 'inactive', 'suspended'], default: 'active' },
    lastLogin: { type: Date },
    loginCount: { type: Number, default: 0 },
    passwordChangedAt: { type: Date },
    authVersion: { type: Number, default: 0, min: 0 },
    mustChangePassword: { type: Boolean, default: false },
    department: { type: String, default: 'SOC' },
  },
  { timestamps: true }
)
UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next()
  this.password = await bcrypt.hash(this.password, 12)
  next()
})
UserSchema.methods.comparePassword = async function (pwd) {
  return bcrypt.compare(pwd, this.password)
}
UserSchema.methods.changedPasswordAfter = function (iat) {
  if (this.passwordChangedAt) return iat < parseInt(this.passwordChangedAt.getTime() / 1000)
  return false
}
UserSchema.methods.toJSON = function () {
  const obj = this.toObject()
  delete obj.password
  delete obj.__v
  return obj
}
module.exports = mongoose.model('User', UserSchema)
