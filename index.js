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

module.exports = { checkPassword };
