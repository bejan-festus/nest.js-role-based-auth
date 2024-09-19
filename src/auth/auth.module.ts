import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { UserModule } from 'src/users/user.module';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthToken, AuthTokenSchema } from './models/auth.model';

@Module({
  controllers: [AuthController],
  imports:[UserModule, 
    JwtModule.registerAsync({
      useFactory:(configService:ConfigService)=>({
        secret: configService.get<string>('jwt.jwtAccessSecret'),
        signOptions:{expiresIn:configService.get<string>('jwt.jwtExpiresIn')}
      }),
      inject:[ConfigService],
      global:true
    }),
    MongooseModule.forFeature([{name:AuthToken.name, schema:AuthTokenSchema }]),
  ],
  providers:[AuthService],
  exports:[AuthService]
})
export class AuthModule {}
