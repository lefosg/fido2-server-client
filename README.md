# FIDO2 Server and Client
An implementation of FIDO2 server/client processes,

The purpose of this repo is to clarify how a FIDO2 client and server (referred to as relying party, RP) look like, how they communicate using WebAuthn and what (JSON) objects and parameters are sent from one to the other. 
What happens when a client initiates a registration process? What parameters are sent from the RP to the client? Where and when is WebAuthn API called? These will be answered through code.

This project was heavily influenced by the FIDO Alliance WebAuthn demo https://github.com/fido-alliance/webauthn-demo.