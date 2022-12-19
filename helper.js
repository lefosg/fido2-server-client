const { createHash } = require('crypto');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
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

/**
 * Returns base64url encoded buffer of the given length
 * @param  {Number} len - length of the buffer
 * @return {String}     - base64url random buffer
 */
function randomBase64URLBuffer(len) {
    len = len || 32;
    let buff = crypto.randomBytes(len);
    return base64url(buff);
}

/**
 * Usernames may be stored hashed in the database so we need to compare their hashes
 * @param {String} given username provided at authentication 
 * @param {String} stored username stored in database
 * @returns true/false if username hashes match
 */
function validateUsername(given, stored) {
    return bcrypt.compareSync(given, stored);
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
 * @param {Buffer} buffer 
 * @returns an object containing authData of the attestation object
 */
const parseGetAttestAuthData = (buffer) => {
    //if(buffer.byteLength < 37)
    //    throw new Error('Authenticator Data must be at least 37 bytes long!');
//
    //let rpIdHash      = buffer.slice(0, 32);             buffer = buffer.slice(32);
//
    ///* Flags */
    //let flagsBuffer   = buffer.slice(0, 1);              buffer = buffer.slice(1);
    //let flagsInt      = flagsBuffer[0];
    //let up            = !!(flagsInt & 0x01); // Test of User Presence
    //let uv            = !!(flagsInt & 0x04); // User Verification
    //let at            = !!(flagsInt & 0x40); // Attestation data
    //let ed            = !!(flagsInt & 0x80); // Extension data
    //let flags = {up, uv, at, ed, flagsInt};
//
    //let counterBuffer = buffer.slice(0, 4);               buffer = buffer.slice(4);
    //let counter       = counterBuffer.readUInt32BE(0);
//
    ///* Attested credential data */
    //let aaguid              = undefined;
    //let aaguidBuffer        = undefined;
    //let credIdBuffer        = undefined;
    //let cosePublicKeyBuffer = undefined;
    //let attestationMinLen   = 16 + 2 + 16 + 42; // aaguid + credIdLen + credId + pk
//
//
    //if(at) { // Attested Data
    //    if(buffer.byteLength < attestationMinLen)
    //        throw new Error(`It seems as the Attestation Data flag is set, but the remaining data is smaller than ${attestationMinLen} bytes. You might have set AT flag for the assertion response.`)
//
    //    aaguid              = buffer.slice(0, 16).toString('hex'); buffer = buffer.slice(16);
    //    aaguidBuffer        = `${aaguid.slice(0, 8)}-${aaguid.slice(8, 12)}-${aaguid.slice(12, 16)}-${aaguid.slice(16, 20)}-${aaguid.slice(20)}`;
//
    //    let credIdLenBuffer = buffer.slice(0, 2);                  buffer = buffer.slice(2);
    //    let credIdLen       = credIdLenBuffer.readUInt16BE(0);
    //    credIdBuffer        = buffer.slice(0, credIdLen);          buffer = buffer.slice(credIdLen);
//
    //    let pubKeyLength    = vanillacbor.decodeOnlyFirst(buffer).byteLength;
    //    cosePublicKeyBuffer = buffer.slice(0, pubKeyLength);       buffer = buffer.slice(pubKeyLength);
    //    cosePublicKeyBuffer = cbor.decodeAllSync(cosePublicKeyBuffer);  //added by me
    //    console.log(cosePublicKeyBuffer);
    //}
//
    //let coseExtensionsDataBuffer = undefined;
    //if(ed) { // Extension Data
    //    let extensionsDataLength = vanillacbor.decodeOnlyFirst(buffer).byteLength;
//
    //    coseExtensionsDataBuffer = buffer.slice(0, extensionsDataLength); buffer = buffer.slice(extensionsDataLength);
    //}
//
    //if(buffer.byteLength)
    //    throw new Error('Failed to decode authData! Leftover bytes been detected!');
//
    //return {rpIdHash, counter, flags, counterBuffer, aaguid, credIdBuffer, cosePublicKeyBuffer, coseExtensionsDataBuffer}
    let rpIdHash      = buffer.slice(0, 32);          buffer = buffer.slice(32);
    let flagsBuffer   = buffer.slice(0, 1);              buffer = buffer.slice(1);
    let flagsInt      = flagsBuffer[0];
    let up            = !!(flagsInt & 0x01); // Test of User Presence
    let uv            = !!(flagsInt & 0x04); // User Verification
    let at            = !!(flagsInt & 0x40); // Attestation data
    let ed            = !!(flagsInt & 0x80); // Extension data
    let flags = {up, uv, at, ed, flagsInt};
    let counterBuffer    = buffer.slice(0, 4);           buffer = buffer.slice(4);
    let counter       = counterBuffer.readUInt32BE(0);
    let aaguid        = buffer.slice(0, 16);          buffer = buffer.slice(16);
    let credIDLenBuf  = buffer.slice(0, 2);           buffer = buffer.slice(2);
    let credIDLen     = credIDLenBuf.readUInt16BE(0);
    let credID        = buffer.slice(0, credIDLen);   buffer = buffer.slice(credIDLen);
    let cosePublicKeyBuffer = buffer;

    counter = parseInt(counterBuffer.toString('hex'));
    aaguid  = aaguid.toString('hex');
    credID  = base64url.encode(credID);
    cosePublicKeyBuffer = cbor.decodeAllSync(cosePublicKeyBuffer)[0];
    return {rpIdHash, flags, counter, counterBuffer, aaguid, credID, cosePublicKeyBuffer}
}


/**
 * Takes COSE encoded public key and converts it to RAW PKCS ECDHA key
 * @param  {Buffer} COSEPublicKey - COSE encoded public key
 * @return {Buffer}               - RAW PKCS encoded public key
 */
function COSEECDHAtoPKCS(COSEPublicKey) {
    /* 
       +------+-------+-------+---------+----------------------------------+
       | name | key   | label | type    | description                      |
       |      | type  |       |         |                                  |
       +------+-------+-------+---------+----------------------------------+
       | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
       |      |       |       | tstr    | the COSE Curves registry         |
       |      |       |       |         |                                  |
       | x    | 2     | -2    | bstr    | X Coordinate                     |
       |      |       |       |         |                                  |
       | y    | 2     | -3    | bstr /  | Y Coordinate                     |
       |      |       |       | bool    |                                  |
       |      |       |       |         |                                  |
       | d    | 2     | -4    | bstr    | Private key                      |
       +------+-------+-------+---------+----------------------------------+
    */

        let coseStruct = COSEPublicKey;
        let tag = Buffer.from([0x04]);
        let x   = coseStruct.get(-1);
        let y   = coseStruct.get(-2);

        return Buffer.concat([tag, x, y])
}

module.exports ={
    hash,
    COSEECDHAtoPKCS,
    randomBase64URLBuffer,
    parseGetAttestAuthData,
    parseGetAssertAuthData,
};