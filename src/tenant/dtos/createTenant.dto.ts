import { IsString, MaxLength, MinLength } from "class-validator";


export class createTenantDto {
    @IsString()
    @MinLength(3)
    @MaxLength(30)
    tenantName:string
}