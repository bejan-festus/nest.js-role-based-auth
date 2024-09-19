import { IsNotEmpty } from "class-validator";


export class refreshTokenDto {

    @IsNotEmpty()
    access:string

}