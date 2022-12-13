const { Router } = require('express');
const base64url  = require('base64url');
const cbor = require('cbor');
const fs = require('fs');
const {hash, COSEECDHAtoPKCS, randomBase64URLBuffer, parseGetAttestAuthData} = require('../helper.js')
const User = require('../database/schemas/User');


//RP data/local variables, could have a database containing them
const RPorigin = "http://localhost:3000";
const rpEffectiveDomain = "localhost";
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
router.post('/register/fetchCredOptions', async (request, response) => {
    let {username, attestationType, authenticatorType} = request.body;

    //check if parameters were given
    if (!username || !attestationType || !authenticatorType) {
        response.json({msg:"No username or attestationType or authenticatorType found in register form", status:false});
        return;
    }
    //check if user exists
    let userDB = await User.findOne( { username : username } );  
    if (userDB) {
        response.json({msg:"Already exists!", status:false});
        return;
    }
    //generate the object and send it to the client
    let PublicKeyCredentialCreationOptions = generateAttestationRequest(username, attestationType, authenticatorType);
    //store session variables for later check in the 'webauthn/register/storeCredentials' endpoint
    request.session.challenge = PublicKeyCredentialCreationOptions.challenge;
    request.session.username = username;
    request.session.id = PublicKeyCredentialCreationOptions.user.id;
    //console.log(PublicKeyCredentialCreationOptions);
    response.json({msg: PublicKeyCredentialCreationOptions, status:true});
});

/**
 * In this route the client will make a POST request with the attestation
 * The server calls the handleAttestation function to make all checks necessary
 * Finally we store the credential in the database 
 */
router.post('/register/storeCredentials', async (request, response) => {

    //if request body is empty => credential creation abandonment!
    if (Object.keys(request.body).length === 0) {
        console.log("Abandoned key creation at client side, clearing sessions variables");
        request.session.challenge = "";
        request.session.username = "";
        request.session.id = "";
        return;
    }
    
    //else, the client sent back an authenticator response, so we have to check it
    let authenticatorAttestationResponse = request.body;
    let challenge = request.session.challenge;
    let username = request.session.username;
    let userId = request.session.id;

    let resultP = verifyStoreCredentialsRequest(authenticatorAttestationResponse, challenge);

    resultP.then(async res =>  {

        if (res.result) {
            //Finally, store authenticator, counter, credId, pubicKey in database
            try {  //use try to check if we have a database related error
                console.log("Storing new credentials in database..");
                //UserSchema: userId, username, publicKey, credentialID, counter, format, createdAt->not needed to input, automatically  created
                let pk = res.publicKey;
                let credId = res.credentialID;
                let counter = res.counter;
                let format = res.fmt;
                let newUser = await User.create({  //saves user in DB
                    userId: userId, 
                    username: username, 
                    publicKey: pk.toString(), 
                    credentialID: credId.toString(), 
                    counter: counter, 
                    format: format});
                    response.json({status: true});
            } catch (err) {
                console.log(err);
                response.json({status: false});
            }
        }
    })
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
            /** Important notice
             * We want to send this JSON object to the client, but we don't have buffers in JSON!
             * That's why we encode the buffer to base64 url. The client will decode it
             */
            rp: {
                name: "localhost",
                id: rpEffectiveDomain  
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
                    requireResidentKey: true,  //decide if resident keys will be used or not! Values: true/false. More on resident keys: https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/Resident_Keys.html
                    userVerification: "preferred"  //values: "preferred", "discouraged", "required", more: https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/User_Presence_vs_User_Verification.html
                },
                excludeCredentials: [],  //limit the creation of multiple credentials
                timeout: 30000
              }
        }
}


async function verifyStoreCredentialsRequest(authenticatorAttestationResponse, sessionChallenge) {
    
    /*
    inside the attestation_type_X file there is the AuthenticatorAttestationResponse
    which has 3 core attributes:
    One is the "id": the (1)credentialID
    and then there is the "response" field which contains: (2)attestationObject 
    and (3)clientDataJSON. Both are ArrayBuffers -> decode
    */

    let credentialID = authenticatorAttestationResponse.id;  //for the reference, this is the credential id
    // ---- decoding client data json
    let clientDataJSON = authenticatorAttestationResponse.response.clientDataJSON;
    let clientData     = JSON.parse(base64url.decode(clientDataJSON));
    
    console.log("Client data JSON:");
    console.log(clientData);    
    
    // ---- decoding attestation object
    let attestationObject       = authenticatorAttestationResponse.response.attestationObject;
    let attestationObjectBuffer = base64url.toBuffer(attestationObject);
    let ctapMakeCredResp        = cbor.decodeAllSync(attestationObjectBuffer)[0];  //CTAP2 encodes with CBOR, so we must decode
    
    console.log("Client attestation object:");
    console.log(ctapMakeCredResp);
    
    // ---- decoding authData
    
    //authData.publicKey is encoded in COSE_Key format
    let authData = parseGetAttestAuthData(ctapMakeCredResp.authData);  //authData
    console.log("Auth Data:");
    console.log(authData);
    
    // ---- verifying the response

    //1. Check that origin is set to the the origin of your website. If it's not, raise phishing alarm
    console.log("Verifying attestation response...");
    let attestationDomainOrigin = clientData.origin;
    if (attestationDomainOrigin != RPorigin) {
        console.log("Domains do not match. Attestation origin says:", attestationDomainOrigin, "\nRP origin is", RPorigin);
        return {result: false};
    }
    console.log("Domains match");
    
    //2. Check that type is set to either “webauthn.create” or “webauthn.get”. In this script we check for creation
    let operationType = clientData.type;
    if (operationType != operationTypes['create']) {
        console.log("Type of attestation is '" + operationType + "'. It should be", operationTypes['create'],"or",operationTypes['get']);
        return {result: false};
    }
    console.log("Type is", operationTypes['create']);
    
    //3. Check that challenge is set to the challenge you’ve sent
    let attestationObjectChallenge = clientData.challenge;
    if (attestationObjectChallenge != sessionChallenge) {
        console.log("Challenges do not match. Got", attestationObjectChallenge, "while it was", sessionChallenge);
        return {result: false};
    }
    console.log("Challenge matches");
    
    //4. Check that flags have UV or UP flags set
    if (authData.flags['up'] != true || authData.flags['uv'] != true) {
        console.log("Not flag of user presence or verification");
        return {result: false};
    }
    console.log("User is present/verified");
    
    //5. Check the RPID hash
    let rpIdHash = authData.rpIdHash.toString('hex');  //cast buffer to hex string
    if (rpIdHash != ExpectedRPIDHash) {
        console.log("RP hashes do not match. Got", rpIdHash, "expected", ExpectedRPIDHash);
        return {result: false};
    }
    console.log("RPID hashes match");
    
    //6. Check if the authenticator added attestation data, if the RP cares about attestation
    let verificationResult = false;
    if (authData.flags['up'] == true) {  //probably need to verify the attestation!
        console.log("Attestation flag is enabled. Proceeding to check attestation");
        //check attestation format and proceed accordingly
        let attestationFmt = ctapMakeCredResp.fmt;
        verificationResult = handleAttestation(attestationFmt);
        if (verificationResult == false) {
            return {result: false};
        }
    }

    return {
        result: true,
        publicKey: base64url.encode(COSEECDHAtoPKCS(authData.cosePublicKeyBuffer)),
        credentialID: credentialID,
        counter: authData.counter,
        fmt: ctapMakeCredResp.fmt
    };

    
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
