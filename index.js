const CryptoJS = require("crypto-js");
const NodeRSA = require("node-rsa");
const fs = require("fs");

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
 * @param {string} card_no card number
 *
 * @param {string} cvv cvv number behide card
 *
 * @param {string} publicKeyPath path to public key file
 *
 * @return {string} Encrypted card data in string format
 *
 * @example
 *
 *     encrypt("4242420000000006", "123", "./public_key.pub.pem")
 *
 *
 */
const encrypt = (card_no, cvv, publicKeyPath) => {
  const [aesKey, encryptedCardData] = encryptCardData({
    card_no,
    cvv,
  });
  const publicKey = fs.readFileSync(publicKeyPath);
  const encryptedKey = encryptKey(aesKey, publicKey);
  const payload = encryptedKey + MessageKeyDelimiter + encryptedCardData;
  return payload;
};

module.exports = { encrypt };
