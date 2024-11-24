const express= require('express');
const authController = require('../Controller/authController');
const auth = require('../utils/auth');

const authRouter = express.Router();

//Public Routes
authRouter.post('/register',authController.register );
authRouter.post('/login',authController.login );
authRouter.post('/logout',authController.logout );


//Protected Routes
authRouter.get('/me',auth.isAuthenticate,authController.me);
authRouter.get('/users',auth.isAuthenticate,authController.users);



module.exports =authRouter;