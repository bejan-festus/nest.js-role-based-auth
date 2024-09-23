import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { createUserDto } from '../users/dtos/createUser.dto';
import { AuthService } from './auth.service';
import { loginDto } from './dtos/login.dto';
import { refreshTokenDto } from './dtos/refreshToken.dto';
import { forgotPasswordDto } from './dtos/forgotPassword.dto';
import { resetPasswordDto } from './dtos/resetPassword.dto';

@Controller('auth')
export class AuthController {

    constructor(private authService: AuthService) { }

    @Post('signup')
    signup(@Body() reqbody: createUserDto) {

        return this.authService.signup(reqbody)

    }

    @Post('login')
    login(@Body() reqbody: loginDto) {

        return this.authService.login(reqbody)

    }

    @Post('refresh')
    refreshToken(@Body() reqBody: refreshTokenDto) {

        return this.authService.refreshToken(reqBody)
        
    }

    @Post('forgot-password')
    forgotPassword(@Body() reqBody: forgotPasswordDto) {

        this.authService.forgotPassword(reqBody)

        return { message: "Email send to your registered address" }
        
    }

    @Post('reset-password')
    resetPassword(@Body() reqBody:resetPasswordDto){
       return this.authService.resetPassword(reqBody)
    }
}
