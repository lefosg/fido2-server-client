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
function bufferDecode(value) {
    return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

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

var state = {
    createResponse: null,
    publicKeyCredential: null,
    credential: null,
    user: {
        name: "testuser@example.com",
        displayName: "testuser",
    },
}

function setUser() {
    username = $("#email").val();
    state.user.name = username.toLowerCase().replace(/\s/g, '');
    state.user.displayName = username.toLowerCase();
}

function checkUserExists() {
    $.get('https://webauthn.io/user/' + state.user.name + '/exists', {}, null, 'json')
        .done(function (response) {
            return true;
        }).catch(function () {
            return false;
        });
}

function getCredentials() {
    $.get('https://webauthn.io/credential/' + state.user.name, {}, null, 'json')
        .done(function (response) {
            console.log(response)
        });
}

function makeCredential() {
    console.log("Fetching options for new credential");
    if ($("#email").val() === "") {
        alert("Please enter a username");
        return;
    }
    setUser();
    var credential = null;

    var attestation_type = $('#select-attestation').find(':selected').val();
    var authenticator_attachment = $('#select-authenticator').find(':selected').val();

    $.get('https://webauthn.io/makeCredential/' + state.user.name, {
            attType: attestation_type,
            authType: authenticator_attachment
        }, null, 'json')
        .done(function (makeCredentialOptions) {  //received parameters from the RP that setup the credentials registration/attestation
            makeCredentialOptions.publicKey.challenge = bufferDecode(makeCredentialOptions.publicKey.challenge);
            makeCredentialOptions.publicKey.user.id = bufferDecode(makeCredentialOptions.publicKey.user.id);
            if (makeCredentialOptions.publicKey.excludeCredentials) {
                for (var i = 0; i < makeCredentialOptions.publicKey.excludeCredentials.length; i++) {
                    makeCredentialOptions.publicKey.excludeCredentials[i].id = bufferDecode(makeCredentialOptions.publicKey.excludeCredentials[i].id);
                }
            }
            navigator.credentials.create({  //create the credential
                publicKey: makeCredentialOptions.publicKey
            }).then(function (newCredential) {
                console.log("PublicKeyCredential Created");
                console.log(newCredential);
                state.createResponse = newCredential;
                registerNewCredential(newCredential);  //send it back to the server (actually sends the attestation)
            }).catch(function (err) {console.log(err)});
        });
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

