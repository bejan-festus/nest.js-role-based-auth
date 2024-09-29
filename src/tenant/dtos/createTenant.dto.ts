import { IsNotEmpty, IsString } from "class-validator";


export class createTenantDto {
    @IsNotEmpty()
    @IsString()
    tenantName:string

}