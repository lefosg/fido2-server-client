const { Router } = require('express');
const User = require('../database/schemas/User');  //the description of the user object saved in database

const router = Router();

/**
 * Default route - index page
 */
router.get('/', (request, response) => {
    response.render("index");
});

/**
 * In this route the user will ask the server "Does this username exist already in your database?"
 * It doesn't matter if it's on registration or authentication, the check should be done in any case
 */
router.get('/user/:username', async (request, response) => {
    //check if the parameter was given
    if (!request.params) {
        response.send("No parameter given");
        return;
    }
    if (!request.params.username) {
        response.send("Enter a username");
        return;
    }
    if (request.params.username === "") {
        response.send("Enter a username");
        return;
    }
    //check if the user is registered in the database
    let usernameQueried = request.params.username;
    let userDB = await User.findOne( { username : usernameQueried } );  //here we do the search
    console.log(`check user ${usernameQueried} existence:`,userDB?true:false)
    if (userDB) {
        response.json({username: userDB.username, createdAt:userDB.createdAt, status:true});
    } else {
        response.json({msg:"User not found!", status:false});
    }
});


module.exports = router;