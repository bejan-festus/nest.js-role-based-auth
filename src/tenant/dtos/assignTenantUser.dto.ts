import { IsEmail, IsNotEmpty, IsString } from "class-validator";


export class assignTenantUserDto {
    @IsNotEmpty()
    @IsString()
    tenantName:string

    @IsNotEmpty()
    @IsString()
    @IsEmail()
    userEmail:string

}