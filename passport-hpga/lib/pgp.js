const openpgp   = require('openpgp');

const KEYSERVER = 'https://pgp.mit.edu';
const USERID_RE = /^(.*?) ?<(.*?)>$/;
const PGP_RE = /(\-{5}(?:BEGIN|END) PGP [A-Z]*\-{5}|[a-zA-Z0-9\+\/\=]{1,64})/g;

const hkp       = new openpgp.HKP(KEYSERVER);

/**
 * Splits a string like "My Name <myname@a.com>" into `name` an `email`, then
 * returns them in an object.
 *
 * TODO: allow the regex to support incomplete strings (e.g. just an email
 * address, just a name, an email address without arrow brackets, etc.)
 *
 * @param {string} userId string like "My Name <myname@a.com>"
 * @return {object} { name, email } from the userId string
 */
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

/**
 * Extract the first signature's key ID from the given message.
 *
 * @param {openpgp.message.Message | string} msg
 * @return {string} long PGP key ID in uppercase hex
 */
function getSigningKeyId(msg) {
  if (!(msg instanceof openpgp.message.Message)) {
    msg = readArmored(msg);
  }

  let signatures = msg.getSigningKeyIds();

  if (signatures.length <= 0) {
    throw new Error('No signatures applied to message');
  }

  return signatures[0].toHex().toUpperCase();
}

/**
 * Verifies that the given message was signed by the given public key and the
 * content of the message matches the given expected text.
 *
 * @param {openpgp.message.Message | string} msg
 * @param {openpgp.packet.PublicKey} publicKey key of mandatory signature
 * @return {Promise} that returns a { user, email } object, or throws if any
 *    steps during verification fail
 */
async function verify(msg, publicKey) {
  msg = readArmored(msg)

  let publicKeyId = publicKey.primaryKey.keyid.toHex().toUpperCase();

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

  let user = parseUserId(publicKey.getUserIds()[0]);
  user.publicKey = publicKey.toPacketlist().write();
  user.keyId = publicKeyId;

  return { user, data };
}

/**
 * Forwards to openpgp.message.readArmored() after doing some string
 * manipulation to account for missing newlines, etc.
 *
 * @param {string} message PGP armored message string
 * @return {openpgp.message.Message}
 */
function readArmored(message) {
  if (message instanceof openpgp.message.Message) {
    return message;
  }

  let lines = message.match(PGP_RE);
  lines[0] += '\n';
  return openpgp.message.readArmored(lines.join('\n'));
}

/**
 * Calls hkp.lookup() on the keyId, then returns the parsed public key object
 * from the armored text returned by the key server.
 *
 * @param {string} keyId ideally, the long ID of the public key in question
 * @return {openpgp.key.Key}
 */
async function findKey(keyId) {
  let publicKeyArmored = await hkp.lookup({ keyId });
  return openpgp.key.readArmored(publicKeyArmored).keys[0];
}

module.exports = { verify, readArmored, getSigningKeyId, findKey }
