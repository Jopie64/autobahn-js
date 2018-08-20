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

declare module 'log' {

let debug = (...args: any[]) => {};

if (typeof AUTOBAHN_DEBUG !== 'undefined' && AUTOBAHN_DEBUG && typeof console !== 'undefined') {
   debug = (...args: any[]) => console.log(...args);
}

export debug;

}