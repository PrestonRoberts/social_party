const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const partySchema = new Schema ({
    _id: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        auto: true
    },
    host_id: {
        type: String,
        required: true
    },
    name: {
        type: String,
        required: true
    }
})

const Party = mongoose.model('Party', partySchema, 'Party');
module.exports = Party;