import { MiddlewareConsumer, Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { UserModule } from 'src/users/user.module';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthToken, AuthTokenSchema } from './models/auth.model';
import { ResetPassword, ResetPasswordSchema } from './models/resetPassword.model';
import { RolesModule } from 'src/roles/roles.module';
import { tenantConnectionProvider } from 'src/tenant/providers/tenant-connection.provider';
import { TenantModule } from 'src/tenant/tenant.module';
import { TenantsMiddleware } from 'src/tenant/middlewares/tenant.middleware';

@Module({
  controllers: [AuthController],
  imports:[UserModule, RolesModule, TenantModule,
    JwtModule.registerAsync({
      useFactory:()=>({}),
      global:true
    }),
    MongooseModule.forFeature([
      {name:AuthToken.name, schema:AuthTokenSchema },
      {name:ResetPassword.name, schema:ResetPasswordSchema },
    ]),
  ],
  providers:[AuthService, tenantConnectionProvider],
  exports:[AuthService, tenantConnectionProvider]
})
export class AuthModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(TenantsMiddleware).forRoutes('auth/refresh');
  }
}
