const express = require("express");
const Router = express.Router;
const {userModel, purchaseModel, courseModel} = require("../db");
const jwt = require("jsonwebtoken");
const {JWT_USER_PASSWORD} = require("../config");
const {z} = require("zod");
const bcrypt = require("bcrypt");
const userMiddleware = require("../middleware/user");

const userRouter = Router();

userRouter.post("/signup",async (req,res) =>{
    try{
    const requiredBody = z.object({
        email: z.string().min(6).max(100).email(),
        password: z.string().min(6).max(50),
        firstName: z.string().min(3).max(50),
        lastName: z.string().min(1).max(50)
    })

    const parsedData = requiredBody.safeParse(req.body);

    if(!parsedData.success){
        res.json({
            message: "Incorrect format",
        });
        return
    }
    const { email, password, firstName, lastName} = req.body;

    const hashedPassword = await bcrypt.hash(password,5);

    await userModel.create({
        email: email,
        password: hashedPassword,
        firstName: firstName,
        lastName: lastName
    });


    res.json({
        message: "Signed up successfully"
    });
}catch(e){
    res.status(500).json({
        message: "Error while signing up"
    });
}

});

userRouter.post("/signin", async (req,res) =>{
    const email = req.body.email;
    const password = req.body.password;

    const user = await userModel.findOne({
        email: email,
    });
    if(!user){
        res.status(403).json({
            message : "User does not exist"
        });
    }

    const passwordMatch = await bcrypt.compare(password,user.password);

    if(passwordMatch){
        const token = jwt.sign({
            id: user._id,
        }, JWT_USER_PASSWORD);

        res.json({
            token: token
        });
    }else{
    res.status(403).json({
        message: "Incorrect credentials"
    });
}
});

userRouter.get("/purchases", userMiddleware, async(req,res) =>{
    const userId = req.userId;

    const purchases = await purchaseModel.find({
        userId
    })

    let purchasedCourseIds = [];

    for(let i=0;i<purchases.length;i++){
        purchasedCourseIds.push(purchases[i].courseId)
    }

    const coursesData = await courseModel.find({
        // _id: { $in: purchases.map(x => x.courseId)}, ALTERNATIVE APPROACH USING MAP FUNCTION
        _id: { $in: purchasedCourseIds }
    });
    res.json({
        purchases,
        coursesData
    });
});


module.exports = userRouter;

