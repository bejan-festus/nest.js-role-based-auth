import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { HydratedDocument } from 'mongoose';

export type TenantAssignedUserDocument = HydratedDocument<TenantAssignedUser>;

@Schema({ timestamps: true, versionKey: false })
export class TenantAssignedUser {

    @Prop({
        required: true,
        type: mongoose.Types.ObjectId
    })
    tenantId: mongoose.Types.ObjectId;

    @Prop({
        required: true,
        type: mongoose.Types.ObjectId
    })
    userId: mongoose.Types.ObjectId;
    
    
}

export const TenantAssignedUserSchema = SchemaFactory.createForClass(TenantAssignedUser);