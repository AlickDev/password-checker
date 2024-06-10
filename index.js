const crypto = require('crypto');

const algorithm = 'aes-256-ctr';

/**
 * Encrypts a text.
 * @param {string} text - The text to encrypt.
 * @param {string} secretKey - The secret key for encryption (must be 32 bytes).
 * @returns {string} - The encrypted text in hex format.
 */
function encrypt(text, secretKey) {
    if (secretKey.length !== 32) {
        throw new Error('Secret key must be 32 bytes long');
    }
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, Buffer.from(secretKey), iv);
    const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

/**
 * Decrypts an encrypted text.
 * @param {string} hash - The encrypted text in hex format.
 * @param {string} secretKey - The secret key for decryption (must be 32 bytes).
 * @returns {string} - The decrypted text.
 */
function decrypt(hash, secretKey) {
    if (secretKey.length !== 32) {
        throw new Error('Secret key must be 32 bytes long');
    }
    const [ivHex, encryptedText] = hash.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const encrypted = Buffer.from(encryptedText, 'hex');
    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(secretKey), iv);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString();
}

/**
 * Checks if a password is valid.
 * A valid password has at least one character, one number, and a minimum of 6 characters.
 * @param {string} password - The password to check.
 * @returns {boolean} - Returns true if the password is valid, otherwise false.
 */
function checkPassword(password) {
    const hasChar = /[a-zA-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasMinLength = password.length >= 6;
    
    return hasChar && hasNumber && hasMinLength;
}

module.exports = { encrypt, decrypt, checkPassword };
