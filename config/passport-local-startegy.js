const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const User = require('../models/userSchema');

// Configure local strategy for passport
passport.use(
  'local',
  new LocalStrategy({ usernameField: 'email' }, function (
    email,
    password,
    done
  ) {
    User.findOne({ email }, function (error, user) {
      if (error) {
        console.error(`Error in finding user: ${error}`);
        return done(error);
      }

      if (!user || !user.isPasswordCorrect(password)) {
        console.log('Invalid Username/Password');
        return done(null, false);
      }

      // Authentication successful
      return done(null, user);
    });
  })
);

// Serialize user
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

// Deserialize user
passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    if (err) {
      console.error('Error in finding user during deserialization');
      return done(err);
    }
    return done(null, user);
  });
});

// Middleware to check if user is authenticated
passport.checkAuthentication = function (req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  return res.redirect('/users/signin');
};

// Middleware to set authenticated user for views
passport.setAuthenticatedUser = function (req, res, next) {
  if (req.isAuthenticated()) {
    res.locals.user = req.user;
  }
  next();
};

module.exports = passport;
