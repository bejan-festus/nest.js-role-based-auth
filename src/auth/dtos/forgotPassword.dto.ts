import { IsEmail, IsNotEmpty } from "class-validator";


export class forgotPasswordDto {

    @IsNotEmpty()
    @IsEmail()
    email:string

}