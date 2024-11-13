import { Body, Controller, Post, Req, } from '@nestjs/common';
import { AuthService } from './auth.service';
import { loginDto } from './dtos/login.dto';
import { refreshTokenDto } from './dtos/refreshToken.dto';
import { forgotPasswordDto } from './dtos/forgotPassword.dto';
import { resetPasswordDto } from './dtos/resetPassword.dto';
import { signupDto } from './dtos/signup.dto';

@Controller('auth')
export class AuthController {

    constructor(private authService: AuthService) { }

    @Post('signup')
    signup(@Body() reqbody: signupDto) {

        return this.authService.signup(reqbody)

    }

    @Post('login')
    login(@Body() reqbody: loginDto) {

        return this.authService.login(reqbody)

    }

    @Post('refresh')
    refreshToken(@Body() reqBody: refreshTokenDto, @Req(){tenantId}:{tenantId:string}) {

        return this.authService.refreshToken(reqBody, tenantId)
        
    }

    @Post('forgot-password')
    forgotPassword(@Body() reqBody: forgotPasswordDto) {

        this.authService.forgotPassword(reqBody)

        return { message: "Email send to your registered mail address" }
        
    }

    @Post('reset-password')
    resetPassword(@Body() reqBody:resetPasswordDto){
       return this.authService.resetPassword(reqBody)
    }
}
