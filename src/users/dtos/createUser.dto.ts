import { IsEmail, IsNotEmpty, IsOptional, IsString } from "class-validator";


export class createUserDto {
    @IsNotEmpty()
    @IsString()
    firstName:string

    @IsOptional()
    @IsString()
    lastName:string

    @IsNotEmpty()
    @IsEmail({},{ message: 'Enter a valid email' })
    email:string

    @IsNotEmpty()
    @IsString()
    password:string


}