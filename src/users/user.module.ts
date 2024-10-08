import { forwardRef, Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from './user.model';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { AuthModule } from 'src/auth/auth.module';
import { TenantModule } from 'src/tenant/tenant.module';

@Module({
    imports:[
        forwardRef(() => AuthModule),
        TenantModule,
        MongooseModule.forFeature([{name:User.name, schema:UserSchema}]),
    ],
    providers:[UserService],
    exports:[UserService],
    controllers: [UserController]
})
export class UserModule {}
