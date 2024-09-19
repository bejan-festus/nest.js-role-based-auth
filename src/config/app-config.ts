import { registerAs } from '@nestjs/config';

export const appConfig = registerAs('app', () => ({
  environment: process.env.ENVIRONMENT,
  port: process.env.PORT,
  
}));

export const jwtConfig = registerAs('jwt', () => ({
  jwtAccessSecret: process.env.JWT_ACCESS_SECRET,
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET,
  jwtExpiresIn: process.env.JWT_EXPIRES_IN,
  jwtRefreshIn: process.env.JWT_REFRESH_IN,
}));

export const mongoConfig = registerAs('mongo', () => ({
  mongoUri: process.env.MONGODB_URI
}));

export const smtpConfig = registerAs('smtp', () => ({
  smtpHost: process.env.SMTP_HOST,
  smtpUser: process.env.SMTP_USERNAME,
  smtpPassword: process.env.SMTP_PASSWORD,
}));

