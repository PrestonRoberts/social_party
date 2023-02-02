const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const chatMessageSchema = new Schema ({
    _id: {
        type: Schema.Types.ObjectId,
        required: true,
        auto: true
    },
    userId: {
        type: Schema.Types.ObjectId,
        required: true,
    },
    partyId: {
        type: Schema.Types.ObjectId,
        required: true,
    },
    message: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
})

const ChatMessage = mongoose.model('ChatMessage', chatMessageSchema, 'ChatMessage');
module.exports = ChatMessage;