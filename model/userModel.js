const mongoose = require('mongoose');


const userSchema=new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    dateOfBirth: {
        type: Date,
        required: true
    },
    role: {
        type: String,
        enum: ['admin', 'user'],
        default: 'user'
    },
    createdAt:{
        type: Date,
        default: Date.now()
    }
});

module.exports=mongoose.model('User', userSchema,'Users');