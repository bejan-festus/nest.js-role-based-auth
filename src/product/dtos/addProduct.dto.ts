import { IsEmail, IsNotEmpty, IsOptional, IsString } from "class-validator";


export class addProductDto {
    @IsNotEmpty()
    @IsString()
    name:string

    @IsOptional()
    @IsString()
    type:string

}