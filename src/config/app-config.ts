import { registerAs } from '@nestjs/config';

export const appConfig = registerAs('app', () => ({
  environment: process.env.ENVIRONMENT,
  port: process.env.PORT,
  clientUrl: process.env.CLIENT_URL
}));

export const jwtConfig = registerAs('jwt', () => ({
  accessSecret: process.env.JWT_ACCESS_SECRET,
  refreshSecret: process.env.JWT_REFRESH_SECRET,
  forgotPasswordSecret: process.env.JWT_FORGOT_PASSWORD_SECRET,
  accessExpiresIn: process.env.JWT_EXPIRES_IN,
  refreshExpiresIn: process.env.JWT_REFRESH_IN,
  forgotPasswordExpiresIn: process.env.JWT_FORGOT_PASSWORD_EXPIRES_IN,
  tenantEncryptionKey:process.env.JWT_TENANT_SECRET_ENCRYPTION_KEY,
  tenantEncryptionAlgorithm:process.env.JWT_TENANT_SECRET_ENCRYPTION_ALOGORITHM
}));

export const mongoConfig = registerAs('mongo', () => ({
  uri: process.env.MONGODB_URI
}));

export const smtpConfig = registerAs('smtp', () => ({
  host: process.env.SMTP_HOST,
  user: process.env.SMTP_USERNAME,
  password: process.env.SMTP_PASSWORD,
  fromEmail: process.env.SMTP_FROM_MAIL,
}));

