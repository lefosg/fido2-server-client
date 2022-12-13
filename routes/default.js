const { Router } = require('express');

const router = Router();

/**
 * Default route - index page
 */
router.get('/', (request, response) => {
    response.render("index");
});

router.get('/user/:username/exists', (request, response) => {
    //check in database if user exists

});

module.exports = router;