// AGRI LINKK - Client Side Validation

function validateEmail(email) {
    const pattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return pattern.test(email);
}

function validatePassword(password) {
    return password.length >= 6;
}

function validatePhone(phone) {
    const pattern = /^[0-9]{10}$/;
    return pattern.test(phone);
}