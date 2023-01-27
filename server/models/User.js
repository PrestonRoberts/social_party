const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new Schema ({
    _id: {
        type: mongoose.Schema.Types.ObjectId,
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
        unique: true
    },
    searchname: {
        type: String,
        required: true,

    },
    password: {
        type: String,
        required: true
    }
})

const User = mongoose.model('User', userSchema, 'User');
module.exports = User;