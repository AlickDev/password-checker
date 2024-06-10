# password-checker
A simple library to check password validity.
# Example:
const { encrypt, decrypt, checkPassword } = require('password-checker');

// Password validation
console.log(checkPassword('abc123')); // true
console.log(checkPassword('abc'));    // false
console.log(checkPassword('123456')); // false
console.log(checkPassword('abc!@#')); // false

// Encryption and decryption
const myText = 'Hello, World!';
const mySecretKey = '12345678901234567890123456789012'; // 32-byte key

const encryptedText = encrypt(myText, mySecretKey);
console.log('Encrypted:', encryptedText);

const decryptedText = decrypt(encryptedText, mySecretKey);
console.log('Decrypted:', decryptedText);
