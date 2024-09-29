import { forwardRef, Module } from '@nestjs/common';
import { RolesService } from './roles.service';
import { RolesController } from './roles.controller';
import { AuthModule } from 'src/auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';
import { Role, RoleSchema } from './roles.model';
import { TenantModule } from 'src/tenant/tenant.module';

@Module({
  controllers: [RolesController],
  providers: [RolesService],
  imports: [
    forwardRef(() => AuthModule),
    TenantModule,
    MongooseModule.forFeature([{ name: Role.name, schema: RoleSchema }])
  ],
  exports:[RolesService]
})
export class RolesModule { }
