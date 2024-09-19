import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { HydratedDocument } from 'mongoose';

export type AuthTokenDocument = HydratedDocument<AuthToken>;

@Schema({ timestamps: true, versionKey: false })
export class AuthToken {

    @Prop({
        required: true
    })
    access: string;

    @Prop({
        required: true
    })
    refresh: string;

    @Prop({
        required: true,
        type:mongoose.Types.ObjectId
    })
    userId: mongoose.Types.ObjectId;

    
}

export const AuthTokenSchema = SchemaFactory.createForClass(AuthToken);