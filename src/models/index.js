
const User = require('./User')
const EmailCode = require('./EmailCode')
User.hasOne(EmailCode)
EmailCode.belongsTo(User)