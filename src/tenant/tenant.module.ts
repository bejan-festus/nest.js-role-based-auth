import { forwardRef, Module } from '@nestjs/common';
import { TenantController } from './tenant.controller';
import { TenantService } from './tenant.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Tenant, TenantSchema } from './models/tenant.model';
import { TenantAssignedUser, TenantAssignedUserSchema } from './models/tenantAssignedUsers.model';
import { UserModule } from 'src/users/user.module';

@Module({
  controllers: [TenantController],
  providers: [TenantService],
  imports:[forwardRef(()=>UserModule) , MongooseModule.forFeature([
    {name:Tenant.name, schema:TenantSchema},
    {name:TenantAssignedUser.name, schema:TenantAssignedUserSchema}
  ])],
  exports:[TenantService]
})
export class TenantModule {}
