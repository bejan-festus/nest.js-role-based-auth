import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { appConfig, jwtConfig, mongoConfig } from './app-config';
import { MongooseModule } from '@nestjs/mongoose';
import { MailerModule } from '@nestjs-modules/mailer';

@Module({
    imports: [
        ConfigModule.forRoot({
            load: [appConfig, jwtConfig, mongoConfig],
            isGlobal: true,
            cache: true,
        }),
        MongooseModule.forRootAsync({
            useFactory: (ConfigService: ConfigService) => ({
                uri: ConfigService.get<string>('mongo.mongoUri')
            }),
            inject: [ConfigService],
        }),
        MailerModule.forRootAsync({
            useFactory:(configService:ConfigService)=>(
                {
                    transport: {
                      host: configService.get<string>('smtp.smtpHost'),
                      auth: {
                        user: configService.get<string>('smtp.smtpUser'),
                        pass: configService.get<string>('smtp.smtpPassword'),
                      },
                    },
                  }
            ),
            inject:[ConfigService]
        })
    ]
})
export class AppConfigModule { }
