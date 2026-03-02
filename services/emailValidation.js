// backend/services/emailValidation.js

const axios = require('axios');

const validateEmail = async (email) => {
    try {
        const response = await axios.get(
            `https://rapid-email-verifier.fly.dev/api/validate?email=${email}`
        );
        
        const data = response.data;
        
        // Interpretar la respuesta
        let isValid = false;
        let message = 'Email no válido';
        let isDisposable = false;
        let isRoleBased = false;
        
        if (data.status === 'VALID') {
            isValid = true;
            message = 'Email válido';
        } else if (data.status === 'PROBABLY_VALID') {
            isValid = true; // Lo consideramos válido
            message = 'Email probablemente válido';
        } else {
            message = data.status || 'Email no válido';
        }
        
        // Verificar si es email temporal o role-based
        if (data.validations) {
            isDisposable = data.validations.is_disposable || false;
            isRoleBased = data.validations.is_role_based || false;
        }
        
        return {
            isValid,
            isDisposable,
            isRoleBased,
            aliasOf: data.aliasOf || null,
            message
        };
        
    } catch (error) {
        console.error('❌ Error validando email:', error.message);
        return {
            isValid: false,
            isDisposable: false,
            isRoleBased: false,
            message: 'Error en la validación'
        };
    }
};

module.exports = validateEmail;