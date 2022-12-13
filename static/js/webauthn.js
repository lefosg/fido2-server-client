//we use this object to control the user state, nothing special, we use this instead of having many variables
var state = {
    createResponse: null,
    publicKeyCredential: null,
    credential: null,
    user: {
        name: "foo",
        displayName: "foo",
    },
}

function detectWebAuthnSupport() {  //called at <body onload=""> in html
    if (window.PublicKeyCredential === undefined ||
        typeof window.PublicKeyCredential !== "function") {
        $('#register-button').attr("disabled", true);
        $('#login-button').attr("disabled", true);
        alert("WebAuthn is not currently supported by this browser");
        return;
    }
}

function string2buffer(str) {
    return (new Uint8Array(str.length)).map(function (x, i) {
        return str.charCodeAt(i)
    });
}

// Encode an ArrayBuffer into a base64 string.
function bufferEncode(value) {
    return base64js.fromByteArray(value)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}

// Don't drop any blanks
// decode
// probably useless
// function bufferDecode(value) {
//     return Uint8Array.from(atob(value), c => c.charCodeAt(0));
// }

function buffer2string(buf) {
    let str = "";
    if (!(buf.constructor === Uint8Array)) {
        buf = new Uint8Array(buf);
    }
    buf.map(function (x) {
        return str += String.fromCharCode(x)
    });
    return str;
}


function setUser() {
    username = $("#email").val();
    state.user.name = username.toLowerCase().replace(/\s/g, '');
    state.user.displayName = username.toLowerCase();
}

function getCredentials() {
    $.get('https://webauthn.io/credential/' + state.user.name, {}, null, 'json')
        .done(function (response) {
            console.log(response)
        });
}

/**
 * When we receive the PublicKeyCredentialCreationOptions, the id and challenge are encoded in base64
 * to ensure transferability and compatibility with JSON. That's why we preformat the object by 
 * using base64url.decode, before using it
 * @param {JSON} credOptions 
 */
function preformatCredOptions(credOptions) {
    credOptions.challenge = window.base64url['decode'](credOptions.challenge);
    credOptions.user.id = window.base64url['decode'](credOptions.user.id);
}
/**
 * Makes a call to the 'localhost:3000/user/:username' endpoint
 */
async function checkUserExists() {
    setUser();
    console.log("making a call to /user/:username to check user existence..")
    let response = await fetch('http://localhost:3000/user/' + state.user.name, {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json'
        }
    });
    let userExists = await response.json();
    console.log("response:",userExists)
    return userExists.status;
}


async function makeCredential() {
    let userExists = await checkUserExists();
    
    if (userExists) {
        alert("User exists, try another name");
        return;
    }
    
    console.log("making a call to /webauthn/register fetch credentials options")
    if ($("#email").val() === "") {
        alert("Please enter a username");
        return;
    }
    setUser();
    var credential = null;

    var attestation_type = $('#select-attestation').find(':selected').val();
    var authenticator_attachment = $('#select-authenticator').find(':selected').val();

    fetch('http://localhost:3000/webauthn/register', {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username: state.user.name,
            attestationType: attestation_type,
            authenticatorType: authenticator_attachment
        })
    })
    .then(resp => resp.json())
    .then(jsonResp => {  
        /**
         * the server response looks like this: {msg: ..., status: true/false}
         * if status == false, then there was an error, and msg is a string with the message error (we alert it below)
         * if status is not false, then the value of msg is the PublicKeyCredentialCreationOptions, for brevity we call it credentialOptions
         */
        if (!jsonResp.status) {
            alert(jsonResp.msg);
        }
        credentialOptions = jsonResp.msg;
        console.log(credentialOptions);
        preformatCredOptions(credentialOptions);
        console.log(credentialOptions);
        
        if (credentialOptions.publicKey.excludeCredentials) {
            for (var i = 0; i < credentialOptions.publicKey.excludeCredentials.length; i++) {
                credentialOptions.publicKey.excludeCredentials[i].id = bufferDecode(makeCredentialOptions.publicKey.excludeCredentials[i].id);
            }
        }

        //create the credential -> CTAP2 kicks in here
        navigator.credentials.create({  
            publicKey: credentialOptions
        }).then(function (newCredential) {
            console.log("PublicKeyCredential Created");
            console.log(newCredential);
            state.createResponse = newCredential;
            //registerNewCredential(newCredential);  //send it back to the server (actually sends the attestation)
        }).catch(function (err) {console.log(err)});
    })
    .catch(error => console.log(error));

    // $.get('http://localhost:3000/register/' + state.user.name, {
    //         attType: attestation_type,
    //         authType: authenticator_attachment
    //     }, null, 'json')
    //     .done(function (makeCredentialOptions) {  //received parameters from the RP that setup the credentials registration/attestation
    //         makeCredentialOptions.publicKey.challenge = bufferDecode(makeCredentialOptions.publicKey.challenge);
    //         makeCredentialOptions.publicKey.user.id = bufferDecode(makeCredentialOptions.publicKey.user.id);
    //         if (makeCredentialOptions.publicKey.excludeCredentials) {
    //             for (var i = 0; i < makeCredentialOptions.publicKey.excludeCredentials.length; i++) {
    //                 makeCredentialOptions.publicKey.excludeCredentials[i].id = bufferDecode(makeCredentialOptions.publicKey.excludeCredentials[i].id);
    //             }
    //         }
    //         navigator.credentials.create({  //create the credential
    //             publicKey: makeCredentialOptions.publicKey
    //         }).then(function (newCredential) {
    //             console.log("PublicKeyCredential Created");
    //             console.log(newCredential);
    //             state.createResponse = newCredential;
    //             registerNewCredential(newCredential);  //send it back to the server (actually sends the attestation)
    //         }).catch(function (err) {console.log(err)});
    //     });
}

// This should be used to verify the auth data with the server
function registerNewCredential(newCredential) {
    // Move data into Arrays incase it is super long
    let attestationObject = new Uint8Array(newCredential.response.attestationObject);
    let clientDataJSON = new Uint8Array(newCredential.response.clientDataJSON);
    let rawId = new Uint8Array(newCredential.rawId);


    $.ajax({
        url: 'https://webauthn.io/makeCredential',
        type: 'POST',
        data: JSON.stringify({
            id: newCredential.id,
            rawId: bufferEncode(rawId),
            type: newCredential.type,
            response: {
                attestationObject: bufferEncode(attestationObject),
                clientDataJSON: bufferEncode(clientDataJSON),
            },
        }),
        contentType: "application/json; charset=utf-8",
        dataType: "json",
        success: function (response) {
            console.log("response from sending attestation:",response);
            alert("Successful credential creation and sending to the RP");
        }
    });
}


function getAssertion() {
    if ($("#email").val() === "") {
        alert("Please enter a username");
        return;
    }
    setUser();
    $.get('/user/' + state.user.name + '/exists', {}, null, 'json').done(function (response) {
            console.log(response);
        }).then(function () {
            $.get('https://webauthn.io/assertion/' + state.user.name, {}, null, 'json')
                .done(function (makeAssertionOptions) {
                    makeAssertionOptions.publicKey.challenge = bufferDecode(makeAssertionOptions.publicKey.challenge);
                    makeAssertionOptions.publicKey.allowCredentials.forEach(function (listItem) {
                        listItem.id = bufferDecode(listItem.id)
                    });
                    console.log("Assertion options received from the RP");
                    console.log(makeAssertionOptions);
                    navigator.credentials.get({
                            publicKey: makeAssertionOptions.publicKey
                        })
                        .then(function (credential) {
                            console.log(credential);
                            verifyAssertion(credential);  //send assertion back to the RP
                        }).catch(function (err) {
                            console.log(err.name);
                            alert(err.message);
                        });
                });
        })
        .catch(function (error) {
            if (!error.exists) {
                alert("User not found, try registering one first!");
            }
            return;
        });
}

function verifyAssertion(assertedCredential) {
    // Move data into Arrays incase it is super long
    console.log('calling verify')
    let authData = new Uint8Array(assertedCredential.response.authenticatorData);
    let clientDataJSON = new Uint8Array(assertedCredential.response.clientDataJSON);
    let rawId = new Uint8Array(assertedCredential.rawId);
    let sig = new Uint8Array(assertedCredential.response.signature);
    let userHandle = new Uint8Array(assertedCredential.response.userHandle);
    $.ajax({
        url: 'https://webauthn.io/assertion',
        type: 'POST',
        data: JSON.stringify({
            id: assertedCredential.id,
            rawId: bufferEncode(rawId),
            type: assertedCredential.type,
            response: {
                authenticatorData: bufferEncode(authData),
                clientDataJSON: bufferEncode(clientDataJSON),
                signature: bufferEncode(sig),
                userHandle: bufferEncode(userHandle),
            },
        }),
        contentType: "application/json; charset=utf-8",
        dataType: "json",
        success: function (response) {
            window.location = "https://webauthn.io/dashboard"
            console.log(response)
        }
    });
}

function setCurrentUser(userResponse) {
    state.user.name = userResponse.name;
    state.user.displayName = userResponse.display_name;
}


document.getElementById('register-button').addEventListener('click', makeCredential);