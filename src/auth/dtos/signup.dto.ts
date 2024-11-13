import { IsEmail, IsNotEmpty, IsOptional, IsString, Matches, MaxLength, MinLength } from "class-validator";


export class signupDto {
    
    @IsString()
    @MinLength(3)
    @MaxLength(15)
    firstName:string
    
    @IsOptional()
    @IsString()
    @MinLength(3)
    @MaxLength(15)
    lastName:string

    @IsNotEmpty()
    @IsEmail({},{ message: 'Enter a valid email' })
    email:string
    
    @IsString()
    @IsNotEmpty()
    @Matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/, {message:'Enter a valid password'})
    password:string

    @IsString()
    @IsNotEmpty()
    @MinLength(3)
    @MaxLength(30)
    tenantName:string


}