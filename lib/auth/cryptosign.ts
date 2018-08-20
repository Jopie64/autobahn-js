///////////////////////////////////////////////////////////////////////////////
//
//  AutobahnJS - http://autobahn.ws, http://wamp.ws
//
//  A JavaScript library for WAMP ("The Web Application Messaging Protocol").
//
//  Copyright (c) Crossbar.io Technologies GmbH and contributors
//
//  Licensed under the MIT License.
//  http://www.opensource.org/licenses/mit-license.php
//
///////////////////////////////////////////////////////////////////////////////

import * as nacl from 'tweetnacl';
import * as util from '../util';
import * as log from '../log';
import * as connection from '../connection';


export function load_private_key (name: string, force_regenerate: boolean): nacl.SignKeyPair {
    var seed = util.atob(localStorage.getItem(name));
    if (!seed || force_regenerate) {
        seed = nacl.randomBytes(nacl.sign.seedLength);
        localStorage.setItem(name, util.btoa(seed));
        log.debug(`new key seed ${name} saved to local storage!`);
    } else {
        log.debug('key seed "' + name + '" loaded from local storage!');
    }
    return nacl.sign.keyPair.fromSeed(seed);
}


export function delete_private_key (name: string) {
    // FIXME: poor man's secure erase
    for (let i = 0; i < 5; ++i) {
        const seed = nacl.randomBytes(nacl.sign.seedLength);
        localStorage.setItem(name, util.btoa(seed));
        localStorage.setItem(name, '');
        localStorage.removeItem(name);
    }
}

export function sign_challenge (pkey: nacl.SignKeyPair, extra: any) {
   var challenge = util.htob(extra.challenge);
   var signature = nacl.sign.detached(challenge, pkey.secretKey);
   var res = util.btoh(signature) + util.btoh(challenge);
   return res;
}


export function public_key (pkey: nacl.SignKeyPair) {
    return util.btoh(pkey.publicKey);
}

export function create_connection (config) {

    var url = config.url;
    var realm = config.realm;
    var authid = config.authid;
    var pkey = config.pkey;
    var activation_code = config.activation_code;
    var request_new_activation_code = config.request_new_activation_code;
    var serializers = config.serializers;

    if (config.debug) {
        console.log(url);
        console.log(realm);
        console.log(authid);
        console.log(pkey);
        console.log(activation_code);
        console.log(request_new_activation_code);
        console.log(serializers);
    }

    function onchallenge (session, method: string, extra) {
        // we only know how to process WAMP-cryptosign here!
        if (method == "cryptosign") {
            // and to do so, we let above helper sign the
            // WAMP-cryptosign challenge as required
            // and return a signature
            return sign_challenge(pkey, extra);
        } else {
            throw "don't know how to authenticate using '" + method + "'";
        }
    }

    authextra = {
        // forward the client pubkey: this allows us to omit authid as
        // the router can identify us with the pubkey already
        pubkey: public_key(pkey),

        // not yet implemented. a public key the router should provide
        // a trustchain for it's public key. the trustroot can eg be
        // hard-coded in the client, or come from a command line option.
        trustroot: null,

        // not yet implemented. for authenticating the router, this
        // challenge will need to be signed by the router and send back
        // in AUTHENTICATE for client to verify. A string with a hex
        // encoded 32 bytes random value.
        challenge: null,

        // FIXME: at least on NodeJS, it should be possible to implement
        // this additional security measure!
        //channel_binding: 'tls-unique'
        channel_binding: null,

        // you should only provide an activation_code the very first time
        // the key pair used is paired. a token can only be used exactly once
        // and reusing it, even from the original client, will result in an error!
        activation_code: activation_code,

        // if true, request sending a new email with a new activation code
        request_new_activation_code: request_new_activation_code
    }

    // now create a AutobahnJS Connection object
    // with WAMP-cryptosign being the only configured
    // authentication method:
    var _connection = new connection.Connection({
        // this MUST be given
        url: url,

        // this MAY be given - if not, then connect to global user realm
        // if given, the user must have access permissions for the respective
        // management realm (to which both users and fabric nodes are connected)
        realm: realm,

        // this MAY be given (but MUST be given on register/pairing)
        authid: authid,

        // this MUST be given
        authmethods: ["cryptosign"],

        // see above
        onchallenge: onchallenge,

        // see above
        authextra: authextra,

        // WAMP serializers to use
        serializers: config.serializers
    });

    return _connection;
}
