import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { AppConfigModule } from './config/app.config.module';
import { UserModule } from './users/user.module';

@Module({
  imports: [ AppConfigModule, AuthModule, UserModule],
})
export class AppModule {}
