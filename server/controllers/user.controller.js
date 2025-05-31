import UserModel from "../models/user.model.js";
import bcrypt from 'bcryptjs'
import sendEmail from "../config/sendEmail.js";
import verifyEmailTemplate from "../utils/verifyEmailTemplate.js";
import generateAccessToken from "../utils/generateAccessToken.js";
import generateRefreshToken from "../utils/generateRefreshToken.js";
import { request, response } from "express";
import uploadImageCloudinary from "../utils/uploadImageCloudinary.js";
import JsonWebToken from "jsonwebtoken";
//register user controller

export async function registerUserController(request,response){
    try{
        //asking from user
        const {name,email,password} = request.body
        //checking if all info given
        if(!name || !email || !password){
            return response.status(400).json({
                message : "provide required field",
                error : true,
                success : false
            })
        }
        //checking if emAIL IS UNIQUE
        const user = await UserModel.findOne({email})

        if (user){
            return response.json({
                message : "Email registered"
                ,error : true,
                success  :false
            })
        }

        //password to hash
        const salt = await bcrypt.genSalt(10)
        const hashPassword = await bcrypt.hash(password,salt)

        //new user

        const payload = {
            name,
            email,
            password : hashPassword
        }

        const newUser = new UserModel(payload)
        const save = await newUser.save()

        //verify email sent
        const verifyEmailURL = `${process.env.FRONTEND_URL}/verify-email?code=${save?._id}`

        const verifyEmail = await sendEmail({
            sendTo : email,
            subject :"verify email"
            ,html: verifyEmailTemplate({
                name,
                url :verifyEmailURL
            })
        })

        return response.json({
            message: "User created successfully",
            error:false,
            success: true,
            data:save
        })

    }catch(error){
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

//verification email status to true

export async function verifyEmailController(request,response){
    try{
        const  {code} =request.body

        const user= await UserModel.findOne({_id : code})

        if(!user){
            return response.staus(400).json({
                message : "Invalid code",
                error : true,
                success : false
            })
        }

        const updateUser=await UserModel.updateOne({_id: code},{
            verify_email : true
        })

        return response.json({
            message: "Verification email done"
            ,error : false,
            success : true
        })

    }
    catch(error){
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success: false
        })

    }
}

//login controller

export async function loginController(request,response){
    try{
        const {email, password}= request.body
        //ccheck if account is there
        const user = await UserModel.findOne({email:email})
        if(!user){
            return response.status(400).json({
                message : "user not registered",
                error : true,
                success : false
            })
        }
        //check if its active
        if(user.status !== "Active"){
            return response.status(400).json({
                message : "Contact admin",
                error : true,
                success : false
            })
        }
        //compare the password
        const checkPassword = await bcrypt.compare(password,user.password)
        if(!checkPassword){
            return response.status(400).json({
                message : "incorrect password",
                error : true,
                success  : false
            })
        }

        //as everything valid send access(for login , life about 1 day) and refresh token(lifespan according to dev)

        const accessToken= await generateAccessToken(user._id)
        const refreshToken = await generateRefreshToken(user._id)
        
        const cookiesOption = {
            httpOnly : true,
            secure : true,
            sameSite : "None"
        }

        response.cookie('accessToken',accessToken,cookiesOption)
        response.cookie('refreshToken',refreshToken,cookiesOption)

        return response.json({
            message : "Login successful",
            error : false,
            success : true,
            data : {
                accessToken,
                refreshToken
            }
        })

    }
    catch(error){
        return response.status(500).json({
            messsage : error.message|| error,
            error : true,
            success  :false
        })
    }
}

//logout controller

export async function logoutController(request,response){
    try{
        //only logined user should use logout so make middleware

        const userId=request.userId // from middleware

        const cookiesOption = {
            httpOnly : true,
            secure: true,
            sameSite:"None"
        }

        response.clearCookie("accessToken",cookiesOption)
        response.clearCookie("refreshToken",cookiesOption)

        //remove refresh token from database
        const removeRefreshToken = await UserModel.updateOne({_id : userId},{refresh_token : ""})

        return response.json({
            message : "Logout Successful",
            error : false,
            success : true
        })
    }
    catch(error){
        return response.status(500).json({
            message: error.message || error
            ,error : true,
            success :false
        })
    }
}

//upload user avatar
export async function uploadAvatarController(request,response){
    try{
        const userId=request.userId // auth middle ware
        const image =request.file   //multer middle ware
        const upload=await uploadImageCloudinary(image)
        
        const updateUserURL = await UserModel.updateOne({_id:userId},{avatar : upload.secure_url})
        
        return response.json({
            message:"avatar uuploaded",
            error:false,
            success: true,
            data:{
                _id : userId,
                avatar : upload.secure_url
            }
        })

    }
    catch(error){
        return response.status(500).json({
            message : error.message || error,
            error:true,
            success : false
        })
    }
}

//update user details

export async function updateUserDetailsController(request,response){
    try{
        const userId = request.userId // from auth middleware
        const {name,email,password,mobile}=request.body
        let hash=""
        if(password){
            const salt = await bcrypt.salt(10)
            hash=await bcrypt.hash(password,genSalt)
        }
        const existingUser= await UserModel.findById({_id:userId})
        const updateUser = await UserModel.updateOne({_id:userId},{
            name: name||existingUser.name,
            email :email||existingUser.email,
            password : hash||existingUser.password,
            mobile :mobile||existingUser.mobile
        })
        return response.json({
            message : "Details updated",
            error : false,
            success: true,
            data: updateUser
        })

    }
    catch(error){
        return response.status(500).json({
            message:error.message||error,
            error : true,
            success : false
        })
    }
}

//forogot password when not login 

export async function forgotPasswordController(request,response){
    try{
        const { email } = request.body
        //check if user exists
        const user = await UserModel.findOne({ email })
        if (!user) {
            return response.status(400).json({
                message: "User not registered",
                error: true,
                success: false
            });
        }
        //generate otp
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        //update user with otp
        const updateUser = await UserModel.updateOne(
            { _id: user._id },
            {forget_password_otp: otp, forget_password_expiry: Date.now() + 15 * 60 * 1000 } // OTP valid for 15 minutes
        );
        
        //send email with otp
        const sendOtpEmail = await sendEmail({
            sendTo: email,
            subject: "Reset Password OTP",
            html: `<p>Your OTP for resetting password is <strong>${otp}</strong>. It is valid for 15 minutes.</p>`
        });
        return response.json({
            message: "OTP sent to your email",
            error: false,
            success: true
        });

    }
    catch(error){
        return response.status(500).json({
            message : error.message || error,
            error : true, 
            success: false
        })
    }
}

//verify forget passwword controller
export async function verifyForgotPasswordOtpController(request, response) {
    try {
        const { email, otp } = request.body;

        // Check if user exists
        const user = await UserModel.findOne({ email });
        if (!user) {
            return response.status(400).json({
                message: "User not registered",
                error: true,
                success: false
            });
        }

        // Check if OTP is valid and not expired
        if (user.forget_password_otp !== otp || Date.now() > user.forget_password_expiry) {
            return response.status(400).json({
                message: "Invalid or expired OTP",
                error: true,
                success: false
            });
        }

        return response.json({
            message: "otp verified successfully",
            error: false,
            success: true
        });

    } catch (error) {
        return response.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });
    }
}

//reset password controller
export async function resetPasswordController(request, response) {
    try {
        const { email, newPassword, confirmPassword} = request.body;

        // Check if user exists
        const user = await UserModel.findOne({ email });
        if (!user) {
            return response.status(400).json({
                message: "User not registered",
                error: true,
                success: false
            });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(newPassword, salt);
        const confirmHashPassword = await bcrypt.hash(confirmPassword, salt);
        // Check if new password and confirm password match
        if (newPassword !== confirmPassword) {
            return response.status(400).json({
                message: "New password and confirm password do not match",
                error: true,
                success: false
            });
        }
        // Update user's password and clear OTP fields
        const updateUser = await UserModel.updateOne(
            { _id: user._id },
            { password: hashPassword, forget_password_otp: "", forget_password_expiry: null }
        );

        return response.json({
            message: "Password reset successfully",
            error: false,
            success: true
        });

    } catch (error) {
        return response.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });
    }
}

//refresh token controller
export async function refreshTokenController(request, response) {
    try {
        const { refreshToken } = request.cookies.refresh_token || request?.header?.authization?.split(" ")[1];//for mobile app

        if (!refreshToken) {
            return response.status(401).json({
                message: "Refresh token not provided",
                error: true,
                success: false
            });
        }
        const verifyToken = await JsonWebToken.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        if (!verifyToken) {
            return response.status(403).json({
                message: "Invalid refresh token",
                error: true,
                success: false
            });
        }
        const userId = verifyToken._id;
        if (!userId) {
            return response.status(403).json({
                message: "Invalid refresh token",
                error: true,
                success: false
            });
        }

        // Generate new access token
        const newAccessToken = await generateAccessToken(userId);

        const cookiesOption = {
            httpOnly: true,
            secure: true,
            sameSite: "None"
        };
        response.cookie('accessToken', newAccessToken, cookiesOption);
        return response.json({
            message: "New access token generated",
            error: false,
            success: true,
            data: { accessToken }
        });

    } catch (error) {
        return response.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });
    }
}