import { IsEmail, IsNotEmpty, IsString } from "class-validator";


export class loginDto {

    @IsNotEmpty()
    @IsEmail({},{ message: 'Enter a valid email' })
    email:string

    @IsNotEmpty()
    @IsString()
    password:string


}