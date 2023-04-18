/*
 * Middleware for protecting endpoint using JWT verify, 
 * Notices some endpoint doesn't require JWT Auth token.
 */
const jwt = require('jsonwebtoken');
const env = require('../config/database')

/**
 * Routing protection for endpoint using JWT verify
 * @param {*} req | headers['authorization']
 * @param {*} res | permission to consult endpoint 
 */
function verifyToken(req, res, next) {
    try {
        const authHeader = req.headers["authorization"]; // Header
        const token = authHeader && authHeader.split("JWT ").pop(); // Token composition | JWT tokenStringKey

        if (token == null){
            throw('Token no existe')
        }
        // Token verification
        jwt.verify(token, env.secret, (err, user) => {
            if (err){
                throw('Token inválido')
            };
            
            req.user = user;
            next();
        });
    } catch (error) {
        res.status(400).json({success: false, mssg: 'Wrong Token', error: error})
    }
    
}

module.exports = {
    verifyToken
}
