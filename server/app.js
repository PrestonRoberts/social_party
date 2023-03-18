require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const cors = require('cors');

// Database Models
const User = require('./models/User');
const Party = require('./models/Party');
const UserToParty = require('./models/UserToParty');

// server
const app = express();
const port = 3000;

// enable CORS for all routes
app.use(cors());

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
        return res.status(401).send({ message: 'no token provided.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if(err) {
            return res.status(401).send({ message: 'invalid token.' });
        }

        req.userId = decoded.id;

        
        if(!mongoose.Types.ObjectId.isValid(req.userId)) {
            return res.status(400).send({ message: 'invalid id.'})
        }

        next();
    });
}

function authenticateTokenGet(req, res, next) {
    const token = req.headers.authorization.split(' ')[1];

    if(!token) {
        return res.status(401).send({ message: 'no token provided.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if(err) {
            return res.status(401).send({ message: 'invalid token.' });
        }

        req.userId = decoded.id;

        
        if(!mongoose.Types.ObjectId.isValid(req.userId)) {
            return res.status(400).send({ message: 'invalid id.'})
        }

        next();
    });
}

async function authenticateParty(req, res, next) {
    const partyId = req.body.partyId;

    if(!partyId) {
        return res.status(401).send({ message: 'no party id provided.' });
    }

    if(!mongoose.Types.ObjectId.isValid(partyId)) {
        return res.status(400).send({ message: 'invalid id.'})
    }

    const party = await Party.findById(partyId);
    if(!party) {
        return res.status(404).send({ message: 'party not found.' });
    }

    req.party = party;
    req.partyId = partyId;
    next();
}

async function userInPartyCheck(req, res, next) {
    const userToParty = await UserToParty.findOne({ userId: req.userId, partyId: req.partyId });

    if(!userToParty) {
        return res.status(403).send({ message: 'user is not apart of the party.' });
    }

    next();
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function isValidUsername(username) {
    // Check length
    if (username.length < 3 || username.length > 16) {
      return false;
    }
  
    // Check for non-alphanumeric characters
    const usernameRegex = /^[a-zA-Z0-9]+$/;
    if (!usernameRegex.test(username)) {
      return false;
    }
  
    return true;
}

function isStrongPassword(password) {
    // Check length
    if (password.length < 8) {
      return false;
    }
  
    // Check for lowercase letters
    const lowercaseRegex = /[a-z]/;
    if (!lowercaseRegex.test(password)) {
      return false;
    }
  
    // Check for uppercase letters
    const uppercaseRegex = /[A-Z]/;
    if (!uppercaseRegex.test(password)) {
      return false;
    }
  
    // Check for digits
    const digitRegex = /[0-9]/;
    if (!digitRegex.test(password)) {
      return false;
    }
  
    // Check for special characters
    const specialCharRegex = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/;
    if (!specialCharRegex.test(password)) {
      return false;
    }
  
    return true;
}

const wordList1 = ['Kind', 'Gentle', 'Brave', 'Calm', 'Warm', 'Loyal', 'Bold', 'Smart', 'Cheer', 'Alert', 'Happy', 'Nimble', 'Wise', 'Agile', 'Polite'];
const wordList2 = ['Wolf', 'Horse', 'Llama', 'Deer', 'Goat', 'Eagle', 'Swan', 'Bear', 'Lion', 'Tiger', 'Whale', 'Shark', 'Dolphin', 'Goose', 'Giraffe', 'Zebra', 'Camel', 'Frog', 'Snake', 'Turtle'];

function generateName () {
    const randomIndex1 = Math.floor(Math.random() * wordList1.length);
    const randomIndex2 = Math.floor(Math.random() * wordList2.length);
    const name = wordList1[randomIndex1] + wordList2[randomIndex2];
    return name;
}

// register an account
app.post('/register', async (req, res) => {
    if (!req.body.email || !req.body.password) {
        return res.status(200).send({ success: false, message: 'Email, or password is missing.' });
    }

    const {email, password} = req.body;
    
    // valid email
    if (!isValidEmail(email)) {
        return res.status(200).send({ success: false, message: 'email not valid' });
    }

    // valid password
    if(!isStrongPassword(password)) {
        return res.status(200).send({ success: false, message: 'password not strong enough' });
    }

    // check if email already exists
    const existingUser = await User.findOne({searchemail: email.toLowerCase() });
    if (existingUser) {
        return res.status(200).send({ success: false, message: 'email already in use' });
    }

    // encrypt password
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt)

    // create new user
    const username = generateName();
    const user = new User({ email, searchemail: email.toLowerCase(), username: username, password:hashedPassword});
    await user.save();

    // log the user in
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {expiresIn: '7d'});

    return res.send({ success: true, message: 'account created successfully.', token })
})

// log in to account
app.post('/login', async (req, res) => {
    const {email, password} = req.body;

    const user = await User.findOne({ email });

    if (!user) {
        return res.status(200).send({ success: false, message: 'invalid login information.' });
    }

    // check if password matches hashed password
    if (!bcrypt.compareSync(password, user.password)) {
        return res.status(200).send({ success: false, message: 'invalid login information.' });
    }

    // log the user in
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {expiresIn: '7d'});
    return res.status(200).send({ success: true, message: 'user login successfully.', token });
})

// delete account
app.delete('/delete_account', authenticateToken, async (req, res) => {
    const userId = req.userId;

    if(!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(200).send({ success: false, message: 'invalid id.'})
    }

    await User.findByIdAndDelete(userId);

    // leave all parties
    await UserToParty.deleteMany({userId});

    // delete all parties
    const allParties = await Party.find({hostId: userId});

    allParties.forEach(party => {
        deleteParty(party._id)
    })

    return res.send({ success: true, message: 'account deleted successfully.' })
})

// create party
app.post('/create_party', authenticateToken, async (req, res) => {
    const { partyName } = req.body;
    const userId = req.userId;

    const user = await User.findById(userId);

    if(!user) {
        return res.status(200).send({ success: false, message: 'user not found.'})
    }

    // create the party
    const party = new Party({hostId: userId, name: partyName});
    await party.save();

    return res.send({ success: true, message: 'party Created Successfully', partyId: party._id })
})

// join party
app.post('/join_party', authenticateToken, authenticateParty, async (req, res) => {
    if(!req.party) {
        return res.status(200).send({ success: false, message: 'party not found.' });
    }

    if(req.party.hostId == req.userId) {
        return res.status(200).send({ success: false, message: 'user is the host of this party.' });
    }

    let userToParty = await UserToParty.findOne({userId: req.userId, partyId: req.partyId});
    if(userToParty) {
        return res.status(200).send({ success: false, message: 'user is already in the party.' })
    }

    // join the party
    userToParty = new UserToParty({userId: req.userId, partyId: req.partyId});
    await userToParty.save();

    return res.send({ success: true, message: 'joined party successfully.', partyId: req.partyId })
})

// leave party
app.delete('/leave_party', authenticateToken, authenticateParty, userInPartyCheck, async (req, res) => {
    const party = await Party.findById(req.partyId);
    if(!req.party) {
        return res.status(200).send({ success: false, message: 'party not found.' });
    }

    if(req.party.hostId == req.userId) {
        return res.status(200).send({ success: false, message: 'user is the host of this party, they can not leave.' });
    }

    await UserToParty.findOneAndDelete({userId: req.userId, partyId: req.partyId});
    return res.send({ success: true, message: 'user has left the party.' })
})

// delete party
async function deleteParty(partyId) {
    await Party.findOneAndDelete({_id: partyId});
    await UserToParty.deleteMany({partyId});
}

app.delete('/delete_party', authenticateToken, authenticateParty, async (req, res) => {
    if(req.party.hostId != req.userId) {
        return res.status(200).send({ success: false, message: 'user is not the host of this party, they can not delete it.' });
    }

    deleteParty(req.partyId);

    return res.send({ success: true, message: 'party has been deleted successfully.' })
})

// remove another user from the party
app.delete('/remove_user', authenticateToken, authenticateParty, async (req, res) => {
    const { targetUserId } = req.body;

    if(req.party.hostId != req.userId) {
        return res.status(200).send({ success: false, message: 'user is not the host of this party, they can not remove other users.' });
    }

    await UserToParty.findOneAndDelete({ userId: targetUserId, partyId: req.partyId });
    return res.send({ success: true, message: 'user was removedfrom the party.' });
})

// get list of parties
app.get('/get_user_parties', authenticateTokenGet, async (req, res) => {
    const userToParty = await UserToParty.find({ userId: req.userId })

    const partyIds = userToParty.map(data => data.partyId);

    const allParties = await Party.find({ _id: { $in: partyIds } });

    res.send({success: true, data: allParties});
})

// get list of users in a party
app.get('/get_party_userlist', authenticateTokenGet, authenticateParty, userInPartyCheck, async(req, res) => {
    const allUserToParty = await UserToParty.find( {partyId: req.partyId });

    const userIds = allUserToParty.map(data => data.userId);

    const allUsers = await User.find( {_id: { $in: userIds } });

    res.send({success: true, data: allUsers});
})

// change username
app.post('/change_username', authenticateToken, async (req, res) => {
    const { newUsername } = req.body;
    const userId = req.userId;

    if (!newUsername) {
        return res.status(200).send({ success: false, message: 'new username is missing.' });
    }

    if (!isValidUsername(newUsername)) {
        return res.status(200).send({ success: false, message: 'username not valid.' });
    }

    // update the user's username
    await User.findByIdAndUpdate(userId, { username: newUsername });

    return res.status(200).send({ success: true, message: 'username updated successfully.' });
});

// get user profile
app.get('/user_profile', authenticateTokenGet, async (req, res) => {
    const userId = req.userId;

    try {
        // find the user by their ID
        const user = await User.findById(userId);

        if (!user) { 
            return res.status(404).send({ success: false, message: 'user not found.' });
        }

        // extract the user's name
        const { username } = user;

        // send the user's name in the response
        return res.status(200).send({ success: true, username: username });

    } catch (error) {
        return res.status(500).send({ success: false, message: 'an error occurred while fetching user profile.' });
    }
});
