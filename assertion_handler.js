const base64url  = require('base64url');
const cbor = require('cbor');
const fs = require('fs');
const {hash, parseGetAssertAuthData} = require('./helper.js')
const {RPorigin, operationTypes, RPchallenge, ExpectedRPIDHash} = require('./constants.js')

try {

    const assertionFile = fs.readFileSync('./assertion_creds/assertion_cred.json');
    let resp = JSON.parse(assertionFile).response;
    
    // ---- decoding client data json
    let clientDataJSON = resp.clientDataJSON;
    let clientData = JSON.parse(base64url.decode(clientDataJSON));
    
    console.log("Client Data JSON: ");
    console.log(clientData);

    // ---- decoding authenticator data
    let authDataJSON = resp.authenticatorData;
    let authData = JSON.parse(base64url.decode(authDataJSON));
    
    console.log("Authenticator Data:");
    console.log(authData);

} catch(err) {
    console.log(err);
}
