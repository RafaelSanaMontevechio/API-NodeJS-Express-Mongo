const jwt = require('jsonwebtoken');
const authConfig = require('../../config/auth');

/**verifica o token enviado necessarias. */
module.exports = (req, res, next) => {
    const token = req.headers.authorization;

    if (!token)
        return res.status(401).send({ error: 'no token provided' });

    jwt.verify(token, authConfig.secret, (err, decoded) => {
        if (err) return res.status(401).send({ error: 'token invalid' });

        req.userId = decoded.id;

        return next();
    });
}
