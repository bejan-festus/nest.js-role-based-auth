import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { AppConfigModule } from './config/app.config.module';
import { UserModule } from './users/user.module';
import { RolesModule } from './roles/roles.module';
import { ProductModule } from './product/product.module';
import { TenantModule } from './tenant/tenant.module';

@Module({
  imports: [ AppConfigModule, AuthModule,TenantModule, UserModule, RolesModule, ProductModule ],
})
export class AppModule {}
