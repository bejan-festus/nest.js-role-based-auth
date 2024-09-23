import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { appConfig, jwtConfig, mongoConfig, smtpConfig } from './app-config';
import { MongooseModule } from '@nestjs/mongoose';
import { MailerModule } from '@nestjs-modules/mailer';

@Module({
    imports: [
        ConfigModule.forRoot({
            load: [appConfig, jwtConfig, mongoConfig, smtpConfig],
            isGlobal: true,
            cache: true,
        }),
        MongooseModule.forRootAsync({
            useFactory: (ConfigService: ConfigService) => ({
                uri: ConfigService.get<string>('mongo.uri')
            }),
            inject: [ConfigService],
        }),
        MailerModule.forRootAsync({
            useFactory: (configService: ConfigService) => (
                {
                    transport: {
                        host: configService.get<string>('smtp.host'),
                        auth: {
                            user: configService.get<string>('smtp.user'),
                            pass: configService.get<string>('smtp.password'),
                        },
                    },
                }
            ),
            inject: [ConfigService]
        })
    ]
})
export class AppConfigModule { }
