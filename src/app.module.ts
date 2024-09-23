import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { AppConfigModule } from './config/app.config.module';
import { UserModule } from './users/user.module';
import { RolesModule } from './roles/roles.module';

@Module({
  imports: [ AppConfigModule, AuthModule, UserModule, RolesModule],
})
export class AppModule {}
