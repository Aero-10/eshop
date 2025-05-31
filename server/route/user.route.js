import Router from 'express'
import { forgotPasswordController, loginController, logoutController, refreshTokenController, registerUserController, resetPasswordController, updateUserDetailsController, uploadAvatarController, verifyEmailController, verifyForgotPasswordOtpController } from '../controllers/user.controller.js'
import auth from '../middleware/auth.js'
import upload from '../middleware/multer.js'

const userRouter = Router()

userRouter.post('/register',registerUserController)

userRouter.post('/verify-email',verifyEmailController)

userRouter.post('/login',loginController)

userRouter.get('/logout',auth,logoutController)

userRouter.put('/upload-avatar',auth,upload.single('avatar'),uploadAvatarController)

userRouter.put('/update-user',auth,updateUserDetailsController)

userRouter.put('/forgot-password',forgotPasswordController)

userRouter.put('/verify-forgot-password-otp',verifyForgotPasswordOtpController)

userRouter.put('/reset-password',resetPasswordController)

userRouter.post('/new-access-token',refreshTokenController)
export default userRouter