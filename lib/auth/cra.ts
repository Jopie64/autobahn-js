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

// require('assert') would be nice .. but it does not
// work with Google Closure after Browserify
import * as crypto from 'crypto-js';

// PBKDF2-base key derivation function for salted WAMP-CRA
//
export function derive_key (secret: string, salt: any, iterationsArg?: number, keylenArg?: number) {
   const iterations = iterationsArg || 1000;
   const keylen = keylenArg || 32;
   var config = {
      keySize: keylen / 4,
      iterations,
      hasher: crypto.algo.SHA256
   }
   var key = crypto.PBKDF2(secret, salt, config);
   return key.toString(crypto.enc.Base64);
}


export function sign (key: string, challenge: string) {
   return crypto.HmacSHA256(challenge, key).toString(crypto.enc.Base64);
}
