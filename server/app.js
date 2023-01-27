require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const User = require('./models/User');
const Party = require('./models/Party');
const UserToParty = require('./models/UserToParty');

// server
const app = express();
const port = 3000;

app.listen(port, () => console.log(`listening on port ${port}`));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }))

// database
const db_url = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@socialpartycluster.fbrfonj.mongodb.net/?retryWrites=true&w=majority`;
mongoose.connect(db_url, {
    useNewUrlParser: true, 
    useUnifiedTopology: true,
    dbName: "Social_Party_DB"
})

const db = mongoose.connection;

db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function() {
    console.log('connected to mongodb')
})

// helper functions
function authenticateToken(req, res, next) {
    const token = req.body.userToken;

    if(!token) {
        return res.status(401).send({ message: 'No token provided.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if(err) {
            return res.stats(401).send({ message: 'Invalid token' });
        }

        req.userId = decoded.id;
        next();
    })
}

// register an account
app.post('/register', async (req, res) => {
    if (!req.body.email || !req.body.username || !req.body.password) {
        return res.status(400).send({ message: 'Email, username or password is missing.' });
    }

    const {email, username, password} = req.body;

    // valid username length
    if(username.length <= 3 || username.length >= 16) {
        return res.status(400).send({ message: 'Username must be between 3 and 16 characters.' });
    }

    // valid email format
    const regex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    if (!regex.test(email)) {
        return res.status(400).send({ message: 'Email address is not valid.' });
    }

    // search database to see if username exists already
    let existingUser = await User.findOne({ searchname: username.toLowerCase() });
    if (existingUser) {
        return res.status(400).send({ message: 'Username already exists.' });
    }

    existingUser = await User.findOne({searchemail: email.toLowerCase() });
    if (existingUser) {
        return res.status(400).send({ message: 'Email already exists.' });
    }

    // encrypt password
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt)

    // create new user
    const user = new User({ email, searchemail: email.toLowerCase(), username, searchname: username.toLowerCase(), password:hashedPassword});
    await user.save();
    return res.send({ message: 'Account created successfully.' })
})

// delete account
app.delete('/delete_account', authenticateToken, async (req, res) => {
    const userId = req.userId;

    if(!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).send({ message: 'Invalid id.'})
    }

    await User.findByIdAndDelete(userId);

    // leave all parties
    await UserToParty.deleteMany({userId});

    // delete all parties
    const allParties = await Party.find({hostId: userId});

    allParties.forEach(party => {
        deleteParty(party._id)
    })

    return res.send({ message: 'Account deleted successfully.' })
})

// log in to account
app.post('/login', async (req, res) => {
    const {username, password} = req.body;

    const user = await User.findOne({ username });

    if (!user) {
        return res.status(401).send({ message: 'Invalid login information.' });
    }

    // check if password matches hashed password
    if (!bcrypt.compareSync(password, user.password)) {
        return res.status(401).send({ message: 'Invalid login information.' });
    }

    // generate json web token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {expiresIn: '7d'});

    return res.json({message: 'User login successfully.', token });
})

// create party
app.post('/create_party', authenticateToken, async (req, res) => {
    const { partyName } = req.body;
    const userId = req.userId;

    if(!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).send({ message: 'Invalid id.'})
    }

    const user = await User.findById(userId);

    if(!user) {
        return res.status(404).send({message: 'User not found.'})
    }

    // create the party
    const party = new Party({hostId: userId, name: partyName});
    await party.save();

    return res.send({ message: 'Party Created Successfully', partyId: party._id })
})

// join party
app.post('/join_party', authenticateToken, async (req, res) => {
    const { partyId } = req.body;

    if(!mongoose.Types.ObjectId.isValid(partyId)) {
        return res.status(400).send({ message: 'Invalid id.'})
    }

    if(!mongoose.Types.ObjectId.isValid(req.userId)) {
        return res.status(400).send({ message: 'Invalid id.'})
    }

    const party = await Party.findById(partyId);
    if(!party) {
        return res.status(404).send({ message: 'Party not found.' });
    }

    if(party.hostId == req.userId) {
        return res.status(409).send({ message: 'User is the host of this party.' });
    }

    let userToParty = await UserToParty.findOne({userId: req.userId, partyId});
    if(userToParty) {
        return res.status(409).send({ message: 'User is already in the party.' })
    }

    // join the party
    userToParty = new UserToParty({userId: req.userId, partyId: partyId});
    await userToParty.save();

    return res.send({ message: 'Joined party successfully.', partyId: partyId })
})

// leave party
app.delete('/leave_party', authenticateToken, async (req, res) => {
    const { partyId } = req.body;

    if(!mongoose.Types.ObjectId.isValid(partyId)) {
        return res.status(400).send({ message: 'Invalid id.'})
    }

    if(!mongoose.Types.ObjectId.isValid(req.userId)) {
        return res.status(400).send({ message: 'Invalid id.'})
    }

    const party = await Party.findById(partyId);
    if(!party) {
        return res.status(404).send({ message: 'Party not found.' });
    }

    if(party.hostId == req.userId) {
        return res.status(409).send({ message: 'User is the host of this party, they can not leave.' });
    }

    await UserToParty.findOneAndDelete({userId: req.userId, partyId});
    return res.send({ message: 'User has left the party.' })
})

// delete party
async function deleteParty(partyId) {
    await Party.findOneAndDelete({_id: partyId});
    await UserToParty.deleteMany({partyId});
}

app.delete('/delete_party', authenticateToken, async (req, res) => {
    const { partyId } = req.body;

    if(!mongoose.Types.ObjectId.isValid(partyId)) {
        return res.status(400).send({ message: 'Invalid id.'})
    }

    if(!mongoose.Types.ObjectId.isValid(req.userId)) {
        return res.status(400).send({ message: 'Invalid id.'})
    }

    const party = await Party.findById(partyId);
    if(!party) {
        return res.status(404).send({ message: 'Party not found.' });
    }

    if(party.hostId != req.userId) {
        return res.status(409).send({ message: 'User is not the host of this party, they can not delete it.' });
    }

    deleteParty(partyId);

    return res.send({ message: 'Party has been deleted successfully.' })
})

// todo - get list of parties

// todo - get list of users in a party