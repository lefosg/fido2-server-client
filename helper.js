const { createHash } = require('crypto');
const vanillacbor = require('vanillacbor');
const base64url  = require('base64url');
const cbor = require('cbor');

/**
 * Hashes the string according to sha256 algorithm
 * @param {string} string 
 * @returns the hash of the string input - sha256 
 */
function hash(string) {
    return createHash('sha256').update(string).digest('hex');
}

// ASSERTION HELPER FUNCTIONS

function parseGetAssertAuthData(buffer) {
    let rpIdHash      = buffer.slice(0, 32);          buffer = buffer.slice(32);
    let flagsBuf      = buffer.slice(0, 1);           buffer = buffer.slice(1);
    let flags         = flagsBuf[0];
    let counterBuf    = buffer.slice(0, 4);           buffer = buffer.slice(4);
    let counter       = counterBuf.readUInt32BE(0);

    return {rpIdHash, flagsBuf, flags, counter, counterBuf}
}

// ATTESTATION HELPER FUNCTIONS

/**
 * A function parse authData contained in an attestation response object
 * @param {*} buffer 
 * @returns an object containing authData of the attestation object
 */
 const parseGetAttestAuthData = (buffer) => {
    if(buffer.byteLength < 37)
        throw new Error('Authenticator Data must be at least 37 bytes long!');

    let rpIdHash      = buffer.slice(0, 32);             buffer = buffer.slice(32);

    /* Flags */
    let flagsBuffer   = buffer.slice(0, 1);              buffer = buffer.slice(1);
    let flagsInt      = flagsBuffer[0];
    let up            = !!(flagsInt & 0x01); // Test of User Presence
    let uv            = !!(flagsInt & 0x04); // User Verification
    let at            = !!(flagsInt & 0x40); // Attestation data
    let ed            = !!(flagsInt & 0x80); // Extension data
    let flags = {up, uv, at, ed, flagsInt};

    let counterBuffer = buffer.slice(0, 4);               buffer = buffer.slice(4);
    let counter       = counterBuffer.readUInt32BE(0);

    /* Attested credential data */
    let aaguid              = undefined;
    let aaguidBuffer        = undefined;
    let credIdBuffer        = undefined;
    let cosePublicKeyBuffer = undefined;
    let attestationMinLen   = 16 + 2 + 16 + 42; // aaguid + credIdLen + credId + pk


    if(at) { // Attested Data
        if(buffer.byteLength < attestationMinLen)
            throw new Error(`It seems as the Attestation Data flag is set, but the remaining data is smaller than ${attestationMinLen} bytes. You might have set AT flag for the assertion response.`)

        aaguid              = buffer.slice(0, 16).toString('hex'); buffer = buffer.slice(16);
        aaguidBuffer        = `${aaguid.slice(0, 8)}-${aaguid.slice(8, 12)}-${aaguid.slice(12, 16)}-${aaguid.slice(16, 20)}-${aaguid.slice(20)}`;

        let credIdLenBuffer = buffer.slice(0, 2);                  buffer = buffer.slice(2);
        let credIdLen       = credIdLenBuffer.readUInt16BE(0);
        credIdBuffer        = buffer.slice(0, credIdLen);          buffer = buffer.slice(credIdLen);

        let pubKeyLength    = vanillacbor.decodeOnlyFirst(buffer).byteLength;
        cosePublicKeyBuffer = buffer.slice(0, pubKeyLength);       buffer = buffer.slice(pubKeyLength);
        cosePublicKeyBuffer = vanillacbor.decode(cosePublicKeyBuffer);  //added by me
    }

    let coseExtensionsDataBuffer = undefined;
    if(ed) { // Extension Data
        let extensionsDataLength = vanillacbor.decodeOnlyFirst(buffer).byteLength;

        coseExtensionsDataBuffer = buffer.slice(0, extensionsDataLength); buffer = buffer.slice(extensionsDataLength);
    }

    if(buffer.byteLength)
        throw new Error('Failed to decode authData! Leftover bytes been detected!');

    return {rpIdHash, counter, flags, counterBuffer, aaguid, credIdBuffer, cosePublicKeyBuffer, coseExtensionsDataBuffer}
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


module.exports ={
    hash,
    parseGetAttestAuthData,
    handleAttestation,
    parseGetAssertAuthData
};