import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
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
import * as crypto from 'crypto'
import { resetPasswordDto } from './dtos/resetPassword.dto';
import { RolesService } from 'src/roles/roles.service';

@Injectable()
export class AuthService {

    constructor(private userService: UserService, private configService: ConfigService, private jwtService: JwtService, @InjectModel(AuthToken.name) private AuthTokenModel: Model<AuthToken>,
        @InjectModel(ResetPassword.name) private resetPasswordModel: Model<ResetPassword>, private mailService: MailerService, private roleService:RolesService) { }

    async signup(user: createUserDto) {

        const hashedPassword = await this.hashPassword(user.password)

        user = {
            ...user,
            password: hashedPassword
        }

        const createdUser = await this.userService.createUser(user)

        const token = {
            access: this.generateAccessToken({ userId: createdUser._id.toString() }),
            refresh: this.generateRefreshToken({ userId: createdUser._id.toString() }),
            userId: createdUser._id
        }

        this.saveTokens(token)

        return { access: token.access }
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

        const token: AuthToken = {
            userId: user._id,
            access: this.generateAccessToken({ userId: user._id.toString() }),
            refresh: this.generateRefreshToken({ userId: user._id.toString() })
        }

        await this.updateTokenByUserId(token)

        return { access: token.access }

    }

    async refreshToken(accessTokenObj: refreshTokenDto) {
        const tokenDoc: AuthToken = await this.findOneAccessToken(accessTokenObj.access)

        if (!tokenDoc) {
            throw new UnauthorizedException()
        }

        const newToken: AuthToken = {
            userId: tokenDoc.userId,
            access: this.generateAccessToken({ userId: tokenDoc.userId.toString() }),
            refresh: this.generateRefreshToken({ userId: tokenDoc.userId.toString() })
        }

        await this.updateTokenByUserId(newToken)

        return { access: newToken.access }
    }

    findOneAccessToken(token: string) {
        return this.AuthTokenModel.findOne({ access: token }, {access:1})
    }

    async forgotPassword(reqBody: forgotPasswordDto) {
        const emailUser = await this.userService.getUserByEmail(reqBody.email)

        if (emailUser) {

            const resetToken = this.generateResetPasswordToken({ userId: emailUser._id.toString() })

            const isResetTokenExist = await this.resetPasswordModel.findOne({ userId: emailUser._id })

            if (isResetTokenExist) {
                await this.resetPasswordModel.updateOne({ userId: emailUser._id }, { $set: { resetPasswordToken: resetToken } })
            } else {
                await this.resetPasswordModel.create({ userId: emailUser._id, resetPasswordToken: resetToken })
            }

            const message = `${this.configService.get('app.clientUrl')}/forgot-password?token=${resetToken}`;

            const mailObj: ISendMailOptions = {
                from: `Support <${this.configService.get('smtp.fromEmail')}>`,
                to: emailUser.email,
                subject: `Reset password`,
                text: message,
            }

            this.mailService.sendMail(mailObj);
        }

    }


    async resetPassword(reqBody: resetPasswordDto) {
        const isTokenInDb: ResetPassword = await this.resetPasswordModel.findOne({ resetPasswordToken: reqBody.resetToken })

        if (!isTokenInDb) { throw new UnauthorizedException() }

        try {
            const payload: { userId: string, iat: number, exp: number } = await this.jwtService.verifyAsync(isTokenInDb.resetPasswordToken, {
                secret: this.configService.get<string>('jwt.forgotPasswordSecret'),
            });

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
