const express=require('express');
const bodyParser=require('body-parser');
const mongoose=require('mongoose');
const bcrypt=require('bcrypt');
const jwt=require('jsonwebtoken');
const app=express();
app.use(bodyParser.urlencoded({extended:true}));
app.use(bodyParser.json());
mongoose.connect('mongodb://localhost:27017/users', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log(err));
const userSchema=new  mongoose.Schema({
    email:String,
    password:String
});
const User=mongoose.model('User',userSchema);
 app.get('/',(req,res)=>{
    res.json({message:'Hello world!'});
 });
 app.post('/register',async (req,res)=>{
    const {email,password}=req.body;
    const userExists=await User.findOne({email});
    //check if already exists
    if(userExists){
        res.status(400).json({message:'user already exists'});
        return;
    }
    //Hash the password
    const hashedPassword=await bcrypt.hash(password,10);
    //create user
    const user=new User({
        email,
        password:hashedPassword
    });
    await user.save();
    res.json({message:'User registerd'});


 });
 app.post('/login',async (req,res)=>{
    const {email,password}=req.body;
    //find user by email
    const user=await User.findOne({email}) ;
    if(!user){
        res.status(400).json({message:'User not found!'});
        return;
    }
    //compare password
    const passwordMatch= await bcrypt.compare(password,user.password);
    if(!passwordMatch){
        res.status(400).json({message:'Password is incorrect'});
        return;
    }
    //Generate JWT Token
    const token=jwt.sign({email},'secret');
    res.json({message:'User logged in!',token});
 });
 app.get('/logout',(req,res)=>{
    res.json({message:'user logged out!'});

 });
 const authMiddleware=(req,res,next)=>{
    const token=req.header.authorization;
    if(!token){
        res.status(401).json({message:'Unauthorized!'});
        return;
    }
    try{
        const {email}=jwt.verify(token,'secret');
        req.user=email;
        next();
    }catch(err){
        res.status(401).json({message:'unauthorized'});
        return;
    }
 };
 app.get('/protected',authMiddleware,(req,res)=>{
    res.json({message:'Welcome,${req.user}!'});
 });
 app.listen(3000,()=>{
    console.log('server started on port 3000');
 })






