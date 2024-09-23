import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';
import { Resource } from './enums/resource.enum';
import { Action } from './enums/action.enum';

export type RoleDocument = HydratedDocument<Role>;


class Permission {
    @Prop({ required: true, type: String, enum: Resource })
    resource: Resource

    @Prop({
        required: true, type: [{ type: String, enum: Action }]
    })
    actions: Action[]

}

@Schema({ timestamps: true, versionKey: false })
export class Role {

    @Prop({ required: true, type: String, unique:true })
    role: string;

    @Prop({ required: true, type: [Permission]})
    permissions: Permission[];


}

export const RoleSchema = SchemaFactory.createForClass(Role);
