import { BadRequestException, HttpException, HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common';
import { createUserDto } from 'src/users/dtos/createUser.dto';
import { UserService } from 'src/users/user.service';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { AuthToken } from './models/auth.model';
import mongoose, { Model, mongo } from 'mongoose';
import { loginDto } from './dtos/login.dto';
import { refreshTokenDto } from './dtos/refreshToken.dto';
import { forgotPasswordDto } from './dtos/forgotPassword.dto';
import { ResetPassword } from './models/resetPassword.model';
import { ISendMailOptions, MailerService } from '@nestjs-modules/mailer';
import { resetPasswordDto } from './dtos/resetPassword.dto';
import { RolesService } from 'src/roles/roles.service';
import { TenantService } from 'src/tenant/tenant.service';
import { decrypt } from 'src/utils/decrypt.util';

@Injectable()
export class AuthService {

    constructor(private userService: UserService, private configService: ConfigService, private jwtService: JwtService, @InjectModel(AuthToken.name) private AuthTokenModel: Model<AuthToken>,
        @InjectModel(ResetPassword.name) private resetPasswordModel: Model<ResetPassword>, private mailService: MailerService, private roleService: RolesService, private tenantService: TenantService) { }

    async signup(user: createUserDto) {

        const hashedPassword = await this.hashPassword(user.password)

        user = {
            ...user,
            password: hashedPassword
        }

        const createdUser = await this.userService.createUser(user)

        // const token = {
        //     access: this.generateAccessToken({ userId: createdUser._id.toString() }),
        //     refresh: this.generateRefreshToken({ userId: createdUser._id.toString() }),
        //     userId: createdUser._id
        // }

        // this.saveTokens(token)

        // return { access: token.access }
        throw new HttpException('Create tenant to continue', HttpStatus.FAILED_DEPENDENCY);
    }

    async hashPassword(password: string) {

        const rounds = 10

        const hash = await bcrypt.hash(password, rounds);

        return hash

    }

    async verifyPassword(password: string, hash: string) {

        const isMatch = await bcrypt.compare(password, hash);

        return isMatch

    }

    generateAccessToken(payload: { userId: string }) {
        return this.jwtService.sign(payload);
    }

    generateRefreshToken(payload: { userId: string }) {
        return this.jwtService.sign(payload, {
            secret: this.configService.get<string>('jwt.refreshSecret'),
            expiresIn: this.configService.get<string>('jwt.refreshExpiresIn'),
        });
    }

    generateToken(payload: { userId: string }, secret: string, expiresIn: string) {
        return this.jwtService.sign(payload, {
            secret: secret,
            expiresIn: expiresIn,
        });
    }

    generateResetPasswordToken(payload: { userId: string }) {
        return this.jwtService.sign(payload, {
            secret: this.configService.get<string>('jwt.forgotPasswordSecret'),
            expiresIn: this.configService.get<string>('jwt.forgotPasswordExpiresIn'),
        });
    }

    saveTokens(token: AuthToken) {
        const createdToken = new this.AuthTokenModel(token)

        createdToken.save()
    }

    updateTokenByUserId(token: AuthToken) {
        return this.AuthTokenModel.updateOne({ userId: token.userId }, { $set: { access: token.access, refresh: token.refresh } }, { upsert: true })
    }

    async login(userCreds: loginDto) {

        const user = await this.userService.getUserPasswordByEmail(userCreds.email)

        if (!user) {
            throw new UnauthorizedException()
        }

        const isMatch = await this.verifyPassword(userCreds.password, user.password)

        if (!isMatch) {
            throw new UnauthorizedException()
        }

        const userTenant = await this.tenantService.getUserAssignedTenant(user._id)

        if (!userTenant) {
            throw new HttpException('Create tenant to continue', HttpStatus.FAILED_DEPENDENCY);
        }

        const tenant = await this.tenantService.getTenantById(userTenant.tenantId)


        const [accessIv, accessEncrypted] = tenant.jwtAccessSecret.split('.')

        const accessSecret = decrypt(accessEncrypted, accessIv, this.configService.get('jwt.tenantEncryptionAlgorithm'), this.configService.get('jwt.tenantEncryptionKey'))

        const [refreshIv, refreshEncrypted] = tenant.jwtRefreshSecret.split('.')

        const refreshSecret = decrypt(refreshEncrypted, refreshIv, this.configService.get('jwt.tenantEncryptionAlgorithm'), this.configService.get('jwt.tenantEncryptionKey'))

        const token: AuthToken = {
            userId: user._id,
            access: this.generateToken({ userId: user._id.toString() }, accessSecret, this.configService.get<string>('jwt.accessExpiresIn')),
            refresh: this.generateToken({ userId: user._id.toString() }, refreshSecret, this.configService.get<string>('jwt.refreshExpiresIn'))
        }

        await this.updateTokenByUserId(token)

        return { access: token.access }

    }

    async refreshToken(reqBody: refreshTokenDto, tenantId: string) {

        const tokenDoc: AuthToken = await this.findOneAccessToken(reqBody.access)

        if (!tokenDoc) {
            throw new UnauthorizedException()
        }

        const tenant = await this.tenantService.getTenant(tenantId)

        const [iv, encrypted] = tenant.jwtRefreshSecret.split('.')

        const secret = decrypt(encrypted, iv, this.configService.get('jwt.tenantEncryptionAlgorithm'), this.configService.get('jwt.tenantEncryptionKey'))

        try {
            const payload: { userId: string, iat: number, exp: number } = await this.jwtService.verifyAsync(tokenDoc.refresh, {
                secret: secret,
            });

            if (tokenDoc.userId.toString() !== payload.userId) {
                throw new Error();
            }
        } catch (err) {
            throw new UnauthorizedException();
        }

        const newToken: AuthToken = {
            userId: tokenDoc.userId,
            access: this.generateToken({ userId: tokenDoc.userId.toString() }, secret, this.configService.get<string>('jwt.accessExpiresIn')),
            refresh: this.generateToken({ userId: tokenDoc.userId.toString() }, secret, this.configService.get<string>('jwt.refreshExpiresIn'))
        }

        await this.updateTokenByUserId(newToken)

        return { access: newToken.access }
    }

    findOneAccessToken(token: string) {
        return this.AuthTokenModel.findOne({ access: token })
    }


    async forgotPassword(reqBody: forgotPasswordDto) {
        const user = await this.userService.getUserByEmail(reqBody.email)

        if (user) {

            const userAssignedTenant = await this.tenantService.getUserAssignedTenant(user._id)

            const tenant = await this.tenantService.getTenantById(userAssignedTenant.tenantId)

            const [iv, encrypted] = tenant.jwtResetPasswordSecret.split('.')

            const secret = decrypt(encrypted, iv, this.configService.get('jwt.tenantEncryptionAlgorithm'), this.configService.get('jwt.tenantEncryptionKey'))

            const resetToken = this.generateToken({ userId: user._id.toString() }, secret, this.configService.get<string>('jwt.forgotPasswordExpiresIn'))

            await this.resetPasswordModel.updateOne({ userId: user._id }, { $set: { resetPasswordToken: resetToken } }, { upsert: true })

            const message = `${this.configService.get('app.clientUrl')}/forgot-password?token=${resetToken}`;

            const mailObj: ISendMailOptions = {
                from: `Support <${this.configService.get('smtp.fromEmail')}>`,
                to: user.email,
                subject: `Reset password`,
                text: message,
            }

            this.mailService.sendMail(mailObj);
        }

    }


    async resetPassword(reqBody: resetPasswordDto) {
        const token: ResetPassword = await this.resetPasswordModel.findOne({ resetPasswordToken: reqBody.resetToken })

        if (!token) { throw new UnauthorizedException() }

        const userAssignedTenant = await this.tenantService.getUserAssignedTenant(token.userId)

        const tenant = await this.tenantService.getTenantById(userAssignedTenant.tenantId)

        const [iv, encrypted] = tenant.jwtResetPasswordSecret.split('.')

        const secret = decrypt(encrypted, iv, this.configService.get('jwt.tenantEncryptionAlgorithm'), this.configService.get('jwt.tenantEncryptionKey'))

        try {
            const payload: { userId: string, iat: number, exp: number } = await this.jwtService.verifyAsync(token.resetPasswordToken, {secret: secret});

            const newHashedPassword = await this.hashPassword(reqBody.newPassword)

            await this.userService.updatePasswordByUserId(new mongoose.Types.ObjectId(payload.userId), newHashedPassword)

            return { message: "Password changed successfully" }

        } catch {
            throw new UnauthorizedException();
        }
    }

    async getUserPermissions(userId: string) {
        const user = await this.userService.getUserById(userId);

        if (!user) throw new BadRequestException();

        const role = await this.roleService.findOne(user.roleId.toString());
        return role.permissions;
    }




}
