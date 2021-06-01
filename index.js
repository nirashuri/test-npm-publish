const CryptoJS = require("crypto-js");
const NodeRSA = require("node-rsa");
const fs = require('fs');

const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";
const MessageKeyDelimiter = ":::";

const generateKey = (keyLength) => {
  let randomstring = "";
  for (let i = 0; i < keyLength; i++) {
    const rnum = Math.floor(Math.random() * chars.length);
    randomstring += chars.substring(rnum, rnum + 1);
  }
  return randomstring;
};

const encryptCardData = (cardInfo) => {
  const key = generateKey(50);
  const dataAsString = JSON.stringify(cardInfo);
  const aesEncrypted = CryptoJS.AES.encrypt(dataAsString, key);
  const aesKey = aesEncrypted.key + MessageKeyDelimiter + aesEncrypted.iv;
  const encryptedCardData = aesEncrypted.ciphertext.toString();

  return [aesKey, encryptedCardData];
};

const encryptKey = (key, publicKey) => {
  const rsaEncrypt = new NodeRSA(publicKey);
  rsaEncrypt.setOptions({ encryptionScheme: "pkcs1" });
  const encryptedKey = rsaEncrypt.encrypt(key, "base64");

  if (!encryptedKey) throw new Error("invalid public key");

  return encryptedKey;
};

/**
 * Encrypt card data.
 *
 * @param {object} cardInfo include cardNo (number on card) and cvv (cvv behide the card)
 *
 * @param {string} publicKeyPath path to public key file
 *
 * @return {string} Encrypted card data in string format
 *
 * @example
 *
 *     encrypt({
 *       cardNo: "4242420000000006",
 *       cvv: "123"
 *     },
 *     `-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----`)
 *
 */
const encrypt = (cardInfo, publicKeyPath) => {
  const [aesKey, encryptedCardData] = encryptCardData(cardInfo);
  const publicKey = fs.readFileSync(publicKeyPath)
  const encryptedKey = encryptKey(aesKey, publicKey);
  const payload = encryptedKey + MessageKeyDelimiter + encryptedCardData;
  return payload;
};

module.exports = { encrypt };
