const {hash} = require('./helper.js')

//RP data/local variables, could have a database containing them
var RPorigin = "https://webauthnworks.github.io";
var operationTypes = {
    'create' : 'webauthn.create',
    'get' : 'webauthn.get'
};
var RPchallenge = 'oGowikAVGrvxcMnrNt89BcGlZr0UU0Ul_Jo6SDyErkM';  //hardcoded, just for demostration
var ExpectedRPIDHash = hash(RPorigin.slice(8));  //cut 'https://'

module.exports = {
    RPorigin,
    operationTypes,
    RPchallenge,
    ExpectedRPIDHash
}