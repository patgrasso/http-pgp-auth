const openpgp   = require('openpgp');
const fs        = require('fs');

const KEYSERVER = 'https://pgp.mit.edu';
const USERID_RE = /^(.*?) ?<(.*?)>$/;

const hkp       = new openpgp.HKP(KEYSERVER);

const pkCache   = {};

function parseUserId(userId) {
  let match = userId.match(USERID_RE);

  if (match == null) {
    return null;
  }

  return {
    name: match[1],
    email: match[2]
  };
}

async function verify(string) {
  let msg = openpgp.message.readArmored(string);
  let signers = msg.getSigningKeyIds();
  let publicKeyArmored;

  if (signers.length <= 0) {
    throw new Error('No signatures applied to message');
  }

  let publicKeyId = signers[0].toHex().toUpperCase();

  if (pkCache[publicKeyId] != null) {
    publicKeyArmored = pkCache[publicKeyId];
  } else {
    publicKeyArmored = await hkp.lookup({ keyId: signers[0].toHex() });
  }

  let publicKey = openpgp.key.readArmored(publicKeyArmored).keys[0];
  let { data, signatures } = await openpgp.verify({
    message: msg,
    publicKeys: [ publicKey ]
  });
  let signatureOfInterest = signatures.find(({ valid, keyid }) => {
    return valid === true && keyid.toHex().toUpperCase() === publicKeyId;
  });

  if (signatureOfInterest == null) {
    throw { 'error': 'Invalid signature' };
  }

  return { user: parseUserId(publicKey.getUserIds()[0]), data };
}

module.exports = { verify }
