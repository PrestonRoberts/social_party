const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new Schema ({
    _id: {
        type: Schema.Types.ObjectId,
        required: true,
        auto: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    searchemail: {
        type: String,
        required: true,
        unique: true
    },
    username: {
        type: String,
        required: true,
        unique: false
    },
    password: {
        type: String,
        required: true
    }
})

const User = mongoose.model('User', userSchema, 'User');
module.exports = User;