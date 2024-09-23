import { IsNotEmpty, IsString } from "class-validator";


export class resetPasswordDto {

    @IsNotEmpty()
    @IsString()
    resetToken:string

    @IsNotEmpty()
    @IsString()
    newPassword:string

}