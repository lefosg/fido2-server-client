//PublicKeyCredentialOptions object is sent by the RP. Browser/Client can alter some paramaters right now

//In WebAuthn all binary parameters (user.id, challenge etc.) are actually Uint8Arrays and not Base64 strings
//These objects are sent from the RP to the client as JSON

//The Yubiko sample object is shows strings in Base64 form for readability
var PublicKeyCredentialCreationOptionsYubico = {
    challenge: "qNqrdXUrk5S7dCM1MAYH3qSVDXznb-6prQoGqiACR10=",  //randomly generated, prevents replay attacks, must be signed
    rp: {  //rp info
      id: "demo.yubico.com",
      name: "Yubico Demo"
    },
    user: {  //user handle
      displayName: "Yubico demo user",
      id: "bz9ZDfHzOBLycqISTAdWwWIZt8VO-6mT3hBNXS5jwmY="
    },
    pubKeyCredParams: [
      {
        alg: -7,  //see https://www.iana.org/assignments/cose/cose.xhtml#algorithms full registry
        type: "public-key"
      }
    ],
    publicKey: {
      attestation: "direct",  //if RP cares about registration, enable this flag. Values: none (no attestation), direct (do attestation), indirect (let the authenticator decide)
      authenticatorSelection: {
        authenticatorAttachment: "cross-platform",  //can use any authenticator - platform/roaming
        requireResidentKey: false,  //decide if resident keys will be used or not! Values: true/false 
        userVerification: "discouraged"  //https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/User_Presence_vs_User_Verification.html
      },
      excludeCredentials: [],  //limit the creation of multiple credentials
      timeout: 30000
    }
};

//The duo sample object uses Uint8Arrays (correct form)
var PublicKeyCredentialCreationOptionsDuo = {
    challenge: Uint8Array.from(
        "qNqrdXUrk5S7dCM1MAYH3qSVDXznb-6prQoGqiACR10=", c => c.charCodeAt(0)),
    rp: {
        name: "Duo Security",
        id: "duosecurity.com",
    },
    user: {
        id: Uint8Array.from(
            "UZSL85T9AFC", c => c.charCodeAt(0)),
        name: "lee@webauthn.guide",
        displayName: "Lee",
    },
    pubKeyCredParams: [{alg: -7, type: "public-key"}],
    authenticatorSelection: {
        authenticatorAttachment: "cross-platform",
    },
    attestation: "direct",
    timeout: 60000
};


const credential = navigator.credentials.create({
    publicKey: PublicKeyCredentialCreationOptionsDuo
})
.then((a) => console.log(a))
.catch((err) => console.log(err));

console.log(credential);

//The client calls the navigator.credentials.create to get the credentials, and sends them back to
//the RP as an attestation object which is an ArrayBuffer