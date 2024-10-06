// const jwt = require("jsonwebtoken");
// const {JWT_USER_PASSWORD} = require("../config");

// function userMiddleware(req,res,next){
//     const token = req.headers.tokens;
//     const decoded = jwt.verify(token, JWT_USER_PASSWORD);

//     if(decoded){
//         req.userId = decoded.id;
//         next();
//     }else{
//         res.status(403).json({
//             message: "You are not signed in"
//         });
//     }
// }

// module.exports = userMiddleware;

const jwt = require("jsonwebtoken");
const { JWT_USER_PASSWORD } = require("../config");

function userMiddleware(req, res, next) {
    const token = req.headers.token;
    const decoded = jwt.verify(token, JWT_USER_PASSWORD);

    try{
    if (decoded) {
        req.userId = decoded.id;
        next()
    } else {
        res.status(403).json({
            message: "You are not signed in"
        })
    }
}catch(error){
    return res.status(403).json({
        message: " Token verification failed"
    });
}

}

module.exports = userMiddleware;
