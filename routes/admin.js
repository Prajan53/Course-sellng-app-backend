const {Router} = require("express");
const adminRouter = Router();
const {z} = require("zod");
const {adminModel, courseModel} = require("../db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const {JWT_ADMIN_PASSWORD} = require("../config");
const adminMiddleware = require("../middleware/admin");


adminRouter.post("/signup",async (req,res) =>{
    try{
    const requiredBody = z.object({
        email : z.string().min(3).max(100).email(),
        password: z.string().min(6).max(50),
        firstName: z.string().min(3).max(50),
        lastName: z.string().min(1).max(50)
    });

    const parsedData = requiredBody.safeParse(req.body);

    if(!parsedData.success){
        res.json({
            message: "Incorret format"
        });
        return
    }

    const {email, password, firstName, lastName} = req.body

    const hashedPassword = await bcrypt.hash(password,5);

    await adminModel.create({
        email: email,
        password: hashedPassword,
        firstName: firstName,
        lastName: lastName
    });

    res.json({
        message: "Signed up as admin successfully"
    });
}catch(e){
    res.status(500).json({
        message: "Error while signing up as admin"
    });
}

});

adminRouter.post("/signin",async (req,res) =>{
    const {email, password} = req.body;

    const user = await adminModel.findOne({
        email: email
    });

    if(!user){
        res.status(403).json({
            message: "User not found in the db"
        });
    }

    const passwordMatch = await bcrypt.compare(password,user.password);

    if(passwordMatch){
        const token = jwt.sign({
            id: user._id,
        }, JWT_ADMIN_PASSWORD)

    res.json({
        message: "Signed in successfully",
        token: token
    });
}else{
    res.json({
        message: "Incorrect password"
    });
}
});

adminRouter.post("/course", adminMiddleware, async(req,res) =>{
    const adminId = req.userId;

    const {title, description, price, imageUrl} = req.body;

    const course = await courseModel.create({
        title: title,
        description: description,
        price: price,
        imageUrl: imageUrl,
        creatorId: adminId
    });

    res.json({
        message: "Successfully created a course",
        courseId: course._id
    });
});

adminRouter.put("/course", adminMiddleware, async (req,res) =>{
    const adminId = req.userId;

    const { title, description, price, imageUrl, courseId} = req.body;

    const course = await courseModel.updateOne({
        _id: courseId,
        creatorId: adminId
    },{
        title: title,
        description: description,
        price: price,
        imageUrl: imageUrl
    })
    res.json({
        message: "course updated",
        courseId: course._id
    });
});


adminRouter.get("/course/bulk", adminMiddleware, async (req,res) =>{
    const adminId = req.userId;

    const courses = await courseModel.find({
        creatorId: adminId
    });
    res.json({
        message: "Bulk endpoint",
        courses: courses
    });
});

module.exports = adminRouter;
