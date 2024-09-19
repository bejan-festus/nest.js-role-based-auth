import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { createUserDto } from '../users/dtos/createUser.dto';
import { AuthService } from './auth.service';
import { loginDto } from './dtos/login.dto';
import { refreshTokenDto } from './dtos/refreshToken.dto';

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
}
