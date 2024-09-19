import { Controller, Get, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { AuthGuard } from 'src/auth/guards/auth.guard';

@Controller('users')
export class UserController {

    constructor(private userService:UserService){}

    @UseGuards(AuthGuard)
    @Get('get-all-users')
    getAllUsers(){
         return this.userService.getAllUsers()  
    }
}
