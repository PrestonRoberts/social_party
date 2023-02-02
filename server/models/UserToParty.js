const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userToPartySchema = new Schema ({
    userId: {
        type: Schema.Types.ObjectId,
        required: true,
    },
    partyId: {
        type: Schema.Types.ObjectId,
        required: true,
    },
})

const UserToParty = mongoose.model('UserToParty', userToPartySchema, 'UserToParty');
module.exports = UserToParty;