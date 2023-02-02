
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
require('dotenv').config();
const session = require('express-session');  
const passport = require('passport'); 
const passport_local_mongoose = require('passport-local-mongoose');  
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')

//----------------------------------------------------------------------------------------
const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));


app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}))  

app.use(passport.initialize());  

app.use(passport.session())  
//-----------------------------------------------------------------------------

//connect to db
const uri = "mongodb://localhost:27017/userDB";
// const uri_atlas='mongodb+srv://'+process.env.UR_NAME+':'+process.env.QUERY+'@cluster0.0vdlp.mongodb.net/'+process.env.DB_NAME+'?retryWrites=true&w=majority';

mongoose.connect(uri);

//create schema
const schema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    user_:{
        secret:[String],
        title:[String]
    }
})
//---------------Encryption using PLUGIN => Hashing + Salting  ------------------

schema.plugin(passport_local_mongoose); 
schema.plugin(findOrCreate)
//------------------------------------------------------------------------------
//creade model i.e. collection
const login_coll = new mongoose.model('user', schema)

//------------------------------------
passport.use(login_coll.createStrategy()); 

//-------------cookies handling------------------
passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        cb(null, { id: user.id, username: user.username });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});

//-------------- google sign in passport strategy ------------------- 
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
}, function (accessToken, refreshToken, profile, cb) {
    console.log(profile)
    login_coll.findOrCreate(
        { googleId: profile.id },
        function (err, user) {
            return cb(err, user);
        });
}
))

//--------------------------------------------------------------------------
app.get("/", function (req, resp) {
    resp.render('home')
})

//------------------------------google authentication and login----------------

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] })
);


app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });
//---------------------
app.get("/login", function (req, resp) {
    resp.render('login')
})
app.post("/login", function (req, resp) {
    const user = new login_coll({
        username: req.body.username,
        password: req.body.password
    })
    req.login(user, function (err) {
        if (err) {
            resp.redirect('/login')
        } else {
            passport.authenticate('local')(req, resp, function () {
                resp.redirect('/secrets');
            })
        }
    })
})

app.get("/register", function (req, resp) {

    resp.render('register')
})


app.get('/submit', function (req, resp) {
    if (req.isAuthenticated()) {
        resp.render('submit');
    } else {
        resp.redirect('login');
    }
})
app.post('/submit', function (req, resp) {
    const secret_=req.body.secret;
    console.log(req.user.id)
    login_coll.findById(req.user.id,function(err,found_user){
        if(err){
            console.log(err)
        }else{ 
            if(found_user){
                const data_of_user=new login_coll({
                    title:req.body.secret_title,
                    secret:secret_
                })
                login_coll.updateMany({_id:req.user.id},{$push:{"user_.secret":req.body.secret,"user_.title":req.body.secret_title}},{upsert:true},function(err,result){
                    if(err){
                        console.log(err);
                    }else{
                        if(result){
                            resp.redirect('/secrets')
                        }
                    }
                })
                
            }
        }
    })
})
app.get('/secrets',async function (req, resp) {
    if (req.isAuthenticated()) {
        //passport method hai
         login_coll.find({'user_':{$ne: null}},async function(err,user_data){
            if(err){
                console.log('err')
            }else{
                if(user_data){
                    console.log(user_data)
                    // const title=user_data[0].user_.title;
                    // console.log(title)
                    const {user_} =user_data; //object destructering :took only user_ grom obj
                    resp.render('secrets',{user_:user_})
                }
            }
        })
        
    } else {
        resp.redirect('login');
    }
})
app.get('/logout', function (req, resp) {
    req.logout(); 
    resp.redirect('/')
})
app.post("/register", function (req, resp) {
    login_coll.register({ username: req.body.username}, req.body.password, function (err, user) {
        if (err) {
            console.log(err)
            resp.redirect('/login');
        } else {
            passport.authenticate('local')(req, resp, function () {
                resp.redirect('/secrets')
            })
        }
    })

})

// -----------------------------------------------------------------------

app.listen(process.env.PORT || 3000, () => {
    console.log('server is running on port 3000...')
})

