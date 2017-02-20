const nacl = require('tweetnacl');
const xorbuffer = require("buffer-xor");
const sjcl = require('sjcl');
const bip39 = require('bip39');
const ed2curve = require("ed2curve");
const microseconds = require('microseconds');
const Promise = require('promise-polyfill'); // polyfill
const $ = window.$; // you need to include jquery in your html file
var bignum = require('bignum-browserify');

const minPasswordLength = 8;
const minEmailLength = 5; // ??? not sure about this
const salt = 'Duo Market Loves Encryption!!!';
const pbkdf2Iterations = 10000;
const naclSeedSize = 256;
const loginHost = 'http://localhost:4000'; // this is where your login api is hosted
const loginURL = loginHost + '/login';
const registerURL = loginHost + '/register';
const mnemonicEntropyBytes = 16; // 128 bits
const boxNonceBytes = 24;

var Console = console; // remove this in production
var mnemonicCache;

function Uint8fromHex(string) {
    var array = new Uint8Array(string.length / 2);
    for (var i = 0; i < string.length; i += 2) {
        array[i / 2] = parseInt(string.substr(i, 2), 16);
    }
    return array;
}

function Uint8toHex(array) {
    var hex = '';
    for (var i = 0; i < array.length; i += 1) {
        var value = array[i].toString(16);
        if (value.length === 1) {
            value = '0' + value;
        }
        hex += value;
    }
    return hex;
}

// returns nanosecond time at an 8 byte buffer
function getNanoTime() {
    return bignum(microseconds.now()).mul(1000).toBuffer();
}

function validateEmail(email) {
    if (typeof email !== 'string' || email.length < minEmailLength) {
        return false;
    }
    return true;
}

function validatePassword(password) {
    if (typeof password !== 'string' || password.length < minPasswordLength) {
        return false;
    }
    return true;
}

// hash a string, returning a Uint8Array
function hash(string) {
    return new Promise(function(resolve) {
        resolve(Uint8fromHex(sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(string))));
    });
}

// hash a string, returning a Uint8Array
function hashTwice(string) {
    return new Promise(function(resolve) {
        resolve(Uint8fromHex(sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(sjcl.hash.sha256.hash(string)))));
    });
}

// xor two Uint8Arrays (or promises to them), returning a hex string
function xor(array1, array2) {
    return Promise.all([array1, array2]).then(function(hashes) {
        return xorbuffer(Buffer.from(hashes[0]), Buffer.from(hashes[1])).toString('hex');
    });
}

function signKeysFromString(string) {
    return new Promise(function(resolve) {
        resolve(Uint8fromHex(sjcl.codec.hex.fromBits(
            sjcl.misc.pbkdf2(string, salt, pbkdf2Iterations, naclSeedSize)))
        );
    }).then(nacl.sign.keyPair.fromSeed);
}

// convert signing keypair (or promise to one), returning boxing keypair
function signToBoxKeys(signKeys) {
    return signKeys.then(function(signKeys) {
        return {
            publicKey: ed2curve.convertPublicKey(signKeys.publicKey),
            secretKey: ed2curve.convertSecretKey(signKeys.secretKey)
        };
    });
}

function getPublicKey(keys) {
    return Uint8toHex(keys.publicKey);
}

function generateMnemonic() {
    var entropy = Uint8toHex(nacl.randomBytes(mnemonicEntropyBytes));
    return bip39.entropyToMnemonic(entropy);
}

function deriveSecret(email, password) {
    var secret = email + password;
    var singleHash = hash(secret);
    var doubleHash = hashTwice(secret);
    var signKeys = signKeysFromString(secret);
    var loginKey = xor(doubleHash, hash(email));
    return {
        singleHash,
        doubleHash,
        signKeys,
        loginKey
    };
}

function postJSON(data, url) {
    return new Promise(function(resolve, reject) {
        $.ajax({
            type: 'POST',
            url: url,
            data: JSON.stringify(data),
            crossDomain: true,
            contentType: 'application/json'
        })
            .done(resolve)
            .fail(function(jqXHR, textStatus, errorThrown) {
                reject(new Error(errorThrown + ': ' + jqXHR.responseText));
            });
    });
}

// twoFA = true for two factor registration
function register(email, password, mnemonic, twoFA) {
    if (!bip39.validateMnemonic(mnemonic)) {
        return Promise.reject(new Error('Invalid mnemonic under BIP39'));
    }
    // work with the entropy counterpart to the mnemonic (1to1) from hereon
    mnemonic = bip39.mnemonicToEntropy(mnemonic);
    if (!validateEmail(email)) {
        return Promise.reject("Email validation problem");
    }
    if (!validatePassword(password)) {
        return Promise.reject("Password validation problem");
    }

    var secret = deriveSecret(email, password);
    secret.publicSigningKey = secret.signKeys.then(getPublicKey);

    var mnemonicHash = hash(mnemonic).then(Uint8toHex);

    // box mnemonic, returns hex ciphertext and hex nonce
    var mnemonicBox = signToBoxKeys(secret.signKeys).then(function(secretBoxKeys) {
        var mnemonicBuffer = Buffer.from(mnemonic, 'hex'); // mnemonic entropy is hex
        var mnemonicNonce = nacl.randomBytes(boxNonceBytes);
        var mnemonicBox = nacl.box(mnemonicBuffer, mnemonicNonce, secretBoxKeys.publicKey, secretBoxKeys.secretKey);
        return [Uint8toHex(mnemonicBox), Uint8toHex(mnemonicNonce)];
    });
    var signedTwoFA = secret.signKeys.then(function(keys) {
        var b = Buffer.alloc(1);
        if (twoFA) {
            b.writeUInt8(1, 0);
        } else {
            b.writeUInt8(0, 0);
        }
        return nacl.sign(b, keys.secretKey);
    }).then(Uint8toHex);

    // collect all values and post to registration endpoint
    return Promise.all([secret.loginKey, mnemonicHash, secret.publicSigningKey, mnemonicBox, signedTwoFA]).then(function(values) {
        var data = {
            loginKey: values[0],
            mnemonicHash: values[1],
            secretPublicSigningKey: values[2],
            encryptedMnemonic: values[3][0],
            mNonce: values[3][1],
            signedTwoFA: values[4]
        };

        Console.log(data);
        return postJSON(data, registerURL);
    });
}

// twoFA = true for two factor login attempt
// ignored by server, but a bad leak of data, if twoFA not enabled
// you do not have to set twoFA, if it is enabled then server will force a retry with 2FA data
function getMnemonic(email, password, twoFA) {
    if (mnemonicCache) { // use cached mnemonic where possible
        return Promise.resolve(mnemonicCache);
    }
    if (!validateEmail(email)) {
        return Promise.reject("Email validation problem");
    }
    if (!validatePassword(password)) {
        return Promise.reject("Password validation problem");
    }

    var secret = deriveSecret(email, password);
    secret.boxKeys = signToBoxKeys(secret.signKeys);

    // sign challenge with secretSignKeys and request mnemonic box from server
    var mnemonicBox = getMnemonicBox(email, secret, twoFA);

    // decrypt mnemonic using secretBoxKeys
    var mnemonic = Promise.all([mnemonicBox, secret.boxKeys]).then(function(values) {
        var entropy = Buffer.from(nacl.box.open(
            Uint8fromHex(values[0].encryptedMnemonic),
            Uint8fromHex(values[0].mnemonicNonce),
            values[1].publicKey,
            // secretKey is the privatekey of the secret-derived keypair
            values[1].secretKey
        )).toString('hex');
        return bip39.entropyToMnemonic(entropy);
    });
    var mnemonicHash = mnemonic.then(hash).then(Uint8toHex);

    return Promise.all([mnemonic, mnemonicHash]).then(function(values) {
        var mnemonic = values[0];
        var mnemonicHash = values[1];

        mnemonicCache = {
            mnemonic,
            mnemonicHash
        };
        return mnemonicCache;
    });
}

function getMnemonicBox(email, secret, twoFA) {
    return Promise.all([secret.loginKey, secret.signKeys]).then(function(values) {
        var loginKey = values[0];
        var challengeBytes = getNanoTime();
        // secretKey is the privatekey of the secret-derived keypair
        var signedChallenge = Uint8toHex(nacl.sign(challengeBytes, values[1].secretKey));
        return [{
            loginKey,
            signedChallenge
        }, values[1].publicKey];
    }).then(function(vals) {
        var data = vals[0];
        var secretPublicKey = vals[1];
        if (twoFA) {
            return secret.singleHash.then(Uint8toHex).then(function(singleHash) {
                data.secretHash = singleHash;
                data.email = email;
                return postJSON(data, loginURL);
            });
        }
        return new Promise(function(resolve, reject) {
            $.ajax({
                type: 'POST',
                url: loginURL,
                data: JSON.stringify(data),
                crossDomain: true,
                contentType: 'application/json'
            })
                .done(resolve)
                .fail(function(jqXHR, textStatus, errorThrown) {
                    try {
                        var obj = JSON.parse(jqXHR.responseText);
                    } catch ( e ) {
                        // error not json formatted
                        reject(new Error(errorThrown + ': ' + jqXHR.responseText));
                    } finally {
                        if (!obj.signedTwoFA) {
                            reject(new Error(errorThrown + ': ' + jqXHR.responseText));
                        }
                        var fabyte = nacl.sign.open(Uint8fromHex(obj.signedTwoFA), secretPublicKey);
                        if (fabyte == null) {
                            reject(new Error("TwoFA boolean signature does not verify: " + obj.signedTwoFA));
                        }
                        if (Uint8toHex(fabyte) == '01') {
                            resolve(getMnemonicBox(email, secret, true)); //try again but with 2FA
                        } else {
                            reject(new Error("TwoFA boolean verifies, but not to true: " + obj.signedTwoFA));
                        }
                    }
                });
        });
    });
}

module.exports = {
    generateMnemonic,
    register,
    getMnemonic
};
