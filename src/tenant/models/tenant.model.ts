import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type TenantDocument = HydratedDocument<Tenant>;

@Schema({ timestamps: true, versionKey: false })
export class Tenant {

    @Prop({
        required: true,
        unique:true
    })
    tenantName: string;

    @Prop({
        required: true,
        unique:true
    })
    jwtAccessSecret: string;

    @Prop({
        required: true,
        unique:true
    })
    jwtRefreshSecret: string;

    @Prop({
        required: true,
        unique:true
    })
    jwtResetPasswordSecret: string;
    
    
}

export const TenantSchema = SchemaFactory.createForClass(Tenant);