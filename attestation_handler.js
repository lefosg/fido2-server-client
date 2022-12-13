const base64url  = require('base64url');
const cbor = require('cbor');
const fs = require('fs');
const {hash, parseGetAttestAuthData, handleAttestation} = require('./helper.js')
const {RPorigin, operationTypes, RPchallenge, ExpectedRPIDHash} = require('./constants.js')

console.log();

try {

    /*
    inside the attestation_type_X file there is the AuthenticatorAttestationResponse
    which has 3 core attributes:
    One is the "id": the (1)credentialID
    and then there is the "response" field which contains: (2)attestationObject 
    and (3)clientDataJSON. Both are ArrayBuffers -> decode
    */
    const attestationFile = fs.readFileSync("./attestation_creds/attestation_type_none.json");  //load the attestation object here
    
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
    if (attestationObjectChallenge != RPchallenge) {
        console.log("Challenges do not match. Got", attestationObjectChallenge, "while it was", RPchallenge);
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

console.log();