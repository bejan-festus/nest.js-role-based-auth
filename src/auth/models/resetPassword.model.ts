import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { HydratedDocument } from 'mongoose';

export type ResetPasswordDocument = HydratedDocument<ResetPassword>;

@Schema({ timestamps: true, versionKey: false })
export class ResetPassword {

    @Prop({
        required: true
    })
    resetPasswordToken: string;

    @Prop({
        required: true,
        type:mongoose.Types.ObjectId
    })
    userId: mongoose.Types.ObjectId;

    
}

export const ResetPasswordSchema = SchemaFactory.createForClass(ResetPassword);