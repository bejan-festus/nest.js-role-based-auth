import { Controller, Get, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { AuthenticationGuard } from 'src/auth/guards/authentication.guard';

@Controller('users')
export class UserController {

    constructor(private userService:UserService){}

    @UseGuards(AuthenticationGuard)
    @Get('get-all-users')
    getAllUsers(){
         return this.userService.getAllUsers()  
    }
}
