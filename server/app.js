require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs')
const mongoose = require('mongoose')
const User = require('./models/User')

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

// todo - register an account
app.post('/register', async (req, res) => {
    console.log(req.body)
    // get input values
    const {email, username, password} = req.body;
    
    // search database for username
    const existingUser = await User.findOne({
        $or: [
            {username: {$eq: username}},
            {email: {$eq: email}},
        ]
    });

    if (existingUser) {
        return res.status(400).send({ message: 'Username already exists' });
    }

    // encrypt password
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt)

    // create new user
    const user = new User({username, email, hashedPassword});
    await user.save();
    res.send({ message: 'Account created successfully.' })
})

// todo - log in to account
app.post('/login', async (req, res) => {
    // get input values
    const {username, password} = req.body;

    // get the user from the database
    const user = await User.findOne({ username });

    // check if user exists
    if (!user) {
        return res.status(401).send({ message: 'Invalid login information.' });
    }

    // check if password matches hashed password
    if (!bcrypt.compareSync(req.body.password, user.password)) {
        return res.status(401).send({ message: 'Invalid login information.' });
    }

    // generate json web token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {expiresIn: '7d'});

    res.json({ token, user })
})

// todo - create party

// todo - join party

// todo - leave party

// todo - delete party

// deadline - 1/27/2023