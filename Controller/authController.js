const User=require('../model/userModel');
const bcrypt=require('bcrypt');
const jwt=require('jsonwebtoken');
const auth = require('../utils/auth');
require('dotenv').config();




const authController = {
    register:async(request,response) => {
        try{
            //extract detail
            const {name,email,password,dateOfBirth,role} = request.body;
            //Check if the user is already registered

            const user = await User.findOne({email});
            if(user) return response.status(400).json({error: 'User already exists'});
            //Create a new user
            
            const hashedPassword=await bcrypt.hash(password,10);

            const newUser=new User({
                name,
                email,
                password:hashedPassword,
                dateOfBirth,
                role
            });
            await newUser.save();
            return response.status(201).json({message:"User Created Successfully"});
        }
        catch(error){
            response.status(400).json({error: error.message})
        }
        
},
    login:async(request,response) => {
        try{

              //get the username and password from request body
        const {email,password}=request.body;
        const user=await User.findOne({email: email});
        if(!user) return response.status(400).json({message: 'User does not exist'});
        const passwordIsValid=await bcrypt.compare(password,user.password);
        if(!passwordIsValid){
            return response.status(400).json({message:'Invalid Password'});
        }
        const token=jwt.sign({id:user._id},process.env.SECRET_KEY);
        console.log(token);
        //store the token in cookies
        response.cookie('token',token,{httpOnly:true});
        return response.status(200).json({message:'Login Successfull'});
    }
        catch(error){
            response.status(400).json({error: error.message});
            
        }

},
    logout:async(request,response) => {
        try{
            //clear the cookie
            await response.clearCookie('token');
            response.status(200).json({message:'Logout Successfull'})

        }
        catch(error){
            response.status(400).json({error: error.message});
        }
},
    me:async(request,response)=>{
        try{
            //get the user_Id after middleware parsed from token(Auth middleware)
           const userID=request.userID;
           //find the user by ID
           const user=await User.findById(userID).select('-password -_id -__v -createdAt');
           //return user details
        //    return response.status(200).json(user);
           return response.status(200).json({Name:user.name, Email:user.email, Date_of_Birth:user.dateOfBirth,Role:user.role});
        }
        catch{
            return response.status(500).json({message:error.message});
        }
    },
    users:async(request,response)=>{
        try{
            const userID=request.userID;
            const user=await User.findById(userID).select('-password -_id -__v -createdAt');
            if(user.role!='admin') return response.status(400).json({message:"You are not admin to fetch details"});
            const allUsers = await User.find().select('-password -__v -createdAt -_id');
            const usersList = allUsers.map(user => ({
                Name: user.name,
                Email: user.email,
                Date_of_Birth: user.dateOfBirth,
                Role: user.role
            }));
            return response.status(200).json(usersList);
        }
        catch(error){
            return response.status(500).json({ message: error.message });
        }
    }

}


module.exports = authController;