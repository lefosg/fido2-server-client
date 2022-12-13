const { Router } = require('express');
const base64url  = require('base64url');
const cbor = require('cbor');
const fs = require('fs');
const {hash, parseGetAttestAuthData} = require('../helper.js')
const User = require('../database/schemas/User');


//RP data/local variables, could have a database containing them
const RPorigin = "http://localhost";
const operationTypes = {
    'create' : 'webauthn.create',
    'get' : 'webauthn.get'
};
const ExpectedRPIDHash = hash("localhost");  //cut 'https://'

const router = Router();

/**
 * In this route the client will make a POST request saying "I want to register"
 * The server generates the challenge, and packs it in the 
 * PublicKeyCredentialCreationOptions object (this is the variable that reaches the client) 
 * Note: we save all information related to the client with express sessions
 */
router.post('/register', async (request, response) => {
    let {username, attestationType, authenticatorType} = request.body;
    //check if parameters were given
    if (!username || !attestationType || !authenticatorType) {
        response.send("No username or attestationType or authenticatorType found in register form");
        return;
    }
    //check if user exists
    let userDB = await User.findOne( { username : username } );  
    console.log("A",userDB)
    if (!userDB) {
        response.json({msg:"User not found!"});
    }
    //generate the object and send it to the client
    let PublicKeyCredentialCreationOptions = generateAttestationRequest(username, attestationType, authenticatorType);
    //store session variables for later check in the 'webauthn/register/storeCredentials' endpoint
    request.session.challenge = PublicKeyCredentialCreationOptions.challenge;
    request.session.username = username;

    response.json(PublicKeyCredentialCreationOptions);
});

/**
 * In this route the client will make a POST request with the attestation
 * The server calls the handleAttestation function to make all checks necessary
 * Finally we store the credential in the database 
 */
router.post('/register/storeCredentials', async (request, response) => {
    //get user specific info with request.session.varname
    
    let authenticatorAttestationResponse = request.body;
    let challenge = request.session.challenge;
    let result = verifyStoreCredentialsRequest(authenticatorAttestationResponse, challenge);
});



// ---------- Registration handling ----------
/** Called at 'webauthn/register'
 * Generate the attestation request. Next steps:
 * send it to the client, (the client calls navigator.credentials.create with this object as the parameter)
 * the client creates the AuthenticatorAttestationResponse,
 * the client sends it to the server ('/webauthn/register/storeCredentials' endpoint),
 * server responds with status 'ok' and stores in DB the user. 
 * @param {String} username desired username of the user
 * @param {String} attestationType we let the user select the attestation type
 * @param {String} authenticatorType we let the user select the authenticator type
 * @returns the PublicKeyCredentialCreationOptions that must be sent to the client
 */
function generateAttestationRequest(username, attestationType, authenticatorType) {

    //we must generate the random challenge here
    return {
            challenge: randomBase64URLBuffer(32),  //looks like this: qNqrdXUrk5S7dCM1MAYH3qSVDXznb-6prQoGqiACR10=
    
            rp: {
                name: "localhost",
                id: "localhost"  
            },
    
            user: {  //userHandle, for details see https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/User_Handle.html
                id: randomBase64URLBuffer(),  //give random id
                name: username,
                displayName: username
            },
    
            pubKeyCredParams: [
                {
                    type: "public-key", 
                    alg: -7 // //see https://www.iana.org/assignments/cose/cose.xhtml#algorithms full registry
                }
            ], 

            publicKey: {
                //if RP cares about registration, set this flag. Values: "none"(no attestation), "direct" (do attestation), "indirect" (let the authenticator decide)
                //just for demonstration, in this example we let the user decide the attestation in the frontend
                attestation: attestationType,  
                authenticatorSelection: {
                  authenticatorAttachment: authenticatorType,  //can use any authenticator - platform/roaming, again for this example let the user decide
                  requireResidentKey: false,  //decide if resident keys will be used or not! Values: true/false. More on resident keys: https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/Resident_Keys.html
                  userVerification: "preferred"  //values: "preferred", "discouraged", "required", more: https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/User_Presence_vs_User_Verification.html
                },
                excludeCredentials: [],  //limit the creation of multiple credentials
                timeout: 30000
              }
        }
}


function verifyStoreCredentialsRequest(authenticatorAttestationResponse, sessionChallenge) {

    try {
        
        /*
        inside the attestation_type_X file there is the AuthenticatorAttestationResponse
        which has 3 core attributes:
        One is the "id": the (1)credentialID
        and then there is the "response" field which contains: (2)attestationObject 
        and (3)clientDataJSON. Both are ArrayBuffers -> decode
        */
        const attestationFile = fs.readFileSync("./attestation_creds/attestation_type_none.json");  //TODO: replace with incoming object from client
        //const attestationResponse = authenticatorAttestationResponse;
        // ---- decoding client data json
        let clientDataJSON = JSON.parse(attestationFile).response.clientDataJSON;
        let clientData     = JSON.parse(base64url.decode(clientDataJSON));
        
        console.log("Client data JSON:");
        console.log((clientData));    
        
        // ---- decoding attestation object
        let attestationObject       = JSON.parse(attestationFile).response.attestationObject;
        let attestationObjectBuffer = base64url.toBuffer(attestationObject);
        let ctapMakeCredResp        = cbor.decodeAllSync(attestationObjectBuffer)[0];
        
        console.log("Client attestation object:");
        console.log(ctapMakeCredResp);
        
        // ---- decoding authData
        
        //authData.publicKey is encoded in COSE_Key format
        let userInformation = parseGetAttestAuthData(ctapMakeCredResp.authData);  //authData
        console.log("User Data (authData - authenticator data):");
        console.log(userInformation);
        
        // ---- verifying the response
        
        //1. Check that origin is set to the the origin of your website. If it's not, raise phishing alarm
        console.log("Verifying attestation response...");
        let attestationDomainOrigin = clientData.origin;
        if (attestationDomainOrigin != RPorigin) {
            console.log("Domains do not match. Attestation origin says:", attestationDomainOrigin, "\nRP origin is", RPorigin);
            return;
        }
        console.log("Domains match");
        
        //2. Check that type is set to either “webauthn.create” or “webauthn.get”. In this script we check for creation
        let operationType = clientData.type;
        if (operationType != operationTypes['create']) {
            console.log("Type of attestation is '" + operationType + "'. It should be", operationTypes['create'],"or",operationTypes['get']);
            return;
        }
        console.log("Type is", operationTypes['create']);
        
        //3. Check that challenge is set to the challenge you’ve sent
        let attestationObjectChallenge = clientData.challenge;
        if (attestationObjectChallenge != sessionChallenge) {
            console.log("Challenges do not match. Got", attestationObjectChallenge, "while it was", sessionChallenge);
            return;
        }
        console.log("Challenge matches");
        
        //4. Check that flags have UV or UP flags set
        if (userInformation.flags['up'] != true || userInformation.flags['uv'] != true) {
            console.log("Not flag of user presence or verification");
            return;
        }
        console.log("User is present/verified");
        
        //5. Check the RPID hash
        let rpIdHash = userInformation.rpIdHash.toString('hex');  //cast buffer to hex string
        if (rpIdHash != ExpectedRPIDHash) {
            console.log("RP hashes do not match. Got", rpIdHash, "expected", ExpectedRPIDHash);
            return;
        }
        console.log("RPID hashes match");
        
        //6. Check if the authenticator added attestation data, if the RP cares about attestation
        let verificationResult = false;
        if (userInformation.flags['up'] == true) {  //probably need to verify the attestation!
            console.log("Attestation flag is enabled. Proceeding to check attestation");
            //check attestation format and proceed accordingly
            let attestationFmt = ctapMakeCredResp.fmt;
            verificationResult = handleAttestation(attestationFmt);
        }
        
        //7. Finally store authenticator, counter, credId, pubicKey in a database
        if (verificationResult) {
            console.log("Storing new credentials in database..");
        }

    } catch (err) {
        console.log(err);
    }   
}

/**
 * Handling attestation formats. Definition in the API in the link below
 * @param {string} fmt 
 * @returns true if attestation verification was successfull, else false
 * @link https://www.w3.org/TR/webauthn/#sctn-defined-attestation-formats
 */
function handleAttestation(fmt) {
    if (fmt == "none") {
        console.log("Attestation format is 'none', don't check anything");
    }
    else if (fmt == "packed") {
        //attestation types supported: Basic, Self, AttCA

    } else if (fmt == "fido-u2f") {
        //attestation types supported: Basic, AttCA

    } else if (fmt == "tpm") {
        //attestation types supported: Basic
        
    } else if (fmt == "android-key") {
        //attestation types supported: Basic

    } else if (fmt == "android-safetynet") {
        //attestation types supported: Basic

    } else if (fmt == "apple") {
        //attestation types supported: Anonymization CA

    } else {
        console.log("Attestation type '" + fmt + "' is unknown. Cannot verify attestation");
        return false;
    }

    return true;
}

// ---------- Assertion handling ----------

function handleAssertion() {
    try {

        const assertionFile = fs.readFileSync('./assertion_creds/assertion_cred.json');  //TODO: replace with incoming object from client
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
    
}

module.exports = router;
