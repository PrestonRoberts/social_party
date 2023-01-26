const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userToPartySchema = new Schema ({
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
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    }
})

const UserToParty = mongoose.model('UserToParty', userToPartySchema, 'UserToParty');
module.exports = UserToParty;