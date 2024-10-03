import { IsNotEmpty, IsString, IsEnum, ArrayUnique, ValidateNested } from "class-validator"
import { Resource } from "../enums/resource.enum"
import { Action } from "../enums/action.enum"
import { Type } from "class-transformer"

export class CreateRoleDto {
    @IsNotEmpty()
    @IsString()
    role:string

    @ValidateNested()
    @Type(()=>Permission)
    permissions:Permission[]

}


export class Permission {
    @IsEnum(Resource)
    resource:string

    @IsEnum(Action, {each:true})
    @ArrayUnique()
    actions:Action[]
}
